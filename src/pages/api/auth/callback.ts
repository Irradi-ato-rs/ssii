// src/pages/api/auth/callback.ts
export const prerender = false;

import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfigByDomain } from '../../../config/tenants';

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

async function resolveRole(sub: string, env: any): Promise<string> {
  try {
    const record = await env.VM_TENANT_DIRECTORY?.get(`roles:${sub}`);
    if (!record) return 'operator';
    const { role } = JSON.parse(record);
    const allowed = (env.PRIVATE_ROLE_ALLOWLIST || '').split(',').map((r: string) => r.trim());
    return allowed.includes(role) ? role : 'operator';
  } catch {
    return 'operator';
  }
}

function errorRedirect(code: string): Response {
  const headers = new Headers();
  headers.set('Location', `/login?error=${encodeURIComponent(code)}`);
  return new Response(null, { status: 302, headers });
}

function clearFlowCookies(headers: Headers) {
  headers.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  headers.append('Set-Cookie', 'pkce_verifier=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
}

export const GET: APIRoute = async ({ request, cookies }) => {
  try {
    const requestUrl = new URL(request.url);
    const code = requestUrl.searchParams.get('code');
    const state = requestUrl.searchParams.get('state');
    const idpError = requestUrl.searchParams.get('error');

    if (idpError) {
      console.error('[VoidMetric Auth] IdP error:', idpError);
      const resp = errorRedirect('tenant_access_denied');
      clearFlowCookies(resp.headers);
      return resp;
    }

    if (!code || !state) {
      return errorRedirect('missing_code_or_state');
    }

    // 1. Validate state cookie (CSRF protection)
    const stateCookie = cookies.get('oidc_state');
    if (!stateCookie || stateCookie.value !== state) {
      console.error('[VoidMetric Auth] State mismatch');
      return errorRedirect('invalid_state');
    }

    // 2. Retrieve PKCE verifier
    const pkceCookie = cookies.get('pkce_verifier');
    if (!pkceCookie?.value) {
      console.error('[VoidMetric Auth] Missing PKCE verifier cookie');
      return errorRedirect('invalid_state');
    }
    const codeVerifier = pkceCookie.value;

    // 3. Decode domain, nonce, mode from state
    let domain: string;
    let stateNonce = '';
    let mode = 'login';
    try {
      let base64Payload = state.replace(/-/g, '+').replace(/_/g, '/');
      while (base64Payload.length % 4) base64Payload += '=';
      const decoded = JSON.parse(atob(base64Payload));
      domain = decoded.domain;
      stateNonce = decoded.nonce || '';
      mode = decoded.mode || 'login';
    } catch {
      return errorRedirect('invalid_state');
    }

    // 4. Get tenant config from KV
    const config = await getIdPConfigByDomain(env, domain);
    if (!config) {
      console.error(`[VoidMetric Auth] No IdP config for domain=${domain}`);
      return errorRedirect('tenant_access_denied');
    }

    // 5. Access secrets
    const clientId = env[config.clientIdEnv]?.trim();
    const clientSecret = env[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error(`[VoidMetric Auth] Missing secret for domain=${domain}`);
      return errorRedirect('signin_unavailable');
    }

    // 6. Token exchange (with PKCE code_verifier)
    const rigidCallbackString = 'https://ssii.fzoirm.com/api/auth/callback';
    const useBasicAuth = config.authMethod !== 'client_secret_post';

    let tokenRes: Response;
    if (useBasicAuth) {
      const encoded = btoa(`${clientId}:${clientSecret}`);
      tokenRes = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${encoded}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: rigidCallbackString,
          code_verifier: codeVerifier,
        }),
        signal: AbortSignal.timeout(15_000),
      });
    } else {
      tokenRes = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: rigidCallbackString,
          code_verifier: codeVerifier,
          client_id: clientId,
          client_secret: clientSecret,
        }),
        signal: AbortSignal.timeout(15_000),
      });
    }

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      console.error(`[VoidMetric Auth] Token exchange failed: ${tokenRes.status} ${errBody.slice(0, 200)}`);
      const resp = errorRedirect('token_exchange_failed');
      clearFlowCookies(resp.headers);
      return resp;
    }

    const tokenData = await tokenRes.json();

    if (!tokenData.id_token) {
      console.error('[VoidMetric Auth] No id_token in token response');
      const resp = errorRedirect('missing_id_token');
      clearFlowCookies(resp.headers);
      return resp;
    }

    // 7. Verify ID token (signature + issuer + audience + alg)
    const JWKS = getJwks(config.jwksUri);
    let payload: any;

    try {
      const verified = await jwtVerify(tokenData.id_token, JWKS, {
        issuer: config.issuer,
        audience: clientId,
        algorithms: ['RS256', 'RS384', 'RS512'],
        clockTolerance: '60s',
      });
      payload = verified.payload;
    } catch (err) {
      console.error(`[VoidMetric Auth] ID token verification failed: ${(err as Error).message}`);
      const resp = errorRedirect('invalid_token');
      clearFlowCookies(resp.headers);
      return resp;
    }

    // 8. Validate nonce (replay protection)
    if (payload.nonce !== stateNonce) {
      console.error('[VoidMetric Auth] Nonce mismatch');
      const resp = errorRedirect('invalid_nonce');
      clearFlowCookies(resp.headers);
      return resp;
    }

    const sub = payload.sub;
    const email = payload.email || '';

    if (!sub) {
      const resp = errorRedirect('missing_sub');
      clearFlowCookies(resp.headers);
      return resp;
    }

    // 9. Tenant provisioning (idempotent)
    const tenantId = domain;

    // Mint API key if absent
    let apiKey = await env.VM_TENANT_DIRECTORY.get(`apikey:${tenantId}`);
    if (!apiKey) {
      const randomBytes = new Uint8Array(32);
      crypto.getRandomValues(randomBytes);
      apiKey = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      await env.VM_TENANT_DIRECTORY.put(`apikey:${tenantId}`, apiKey);
      console.log(`[VoidMetric Auth] Minted API key for tenant=${tenantId}`);
    }

    // Ensure portal ownership record exists
    const portalRaw = await env.VM_TENANT_DIRECTORY.get(`portal:${tenantId}`);
    if (!portalRaw) {
      await env.VM_TENANT_DIRECTORY.put(`portal:${tenantId}`, JSON.stringify({ owner: sub }));
      console.log(`[VoidMetric Auth] Created portal record for tenant=${tenantId} owner=${sub}`);
    }

    // Ensure role record exists (default: operator)
    const roleRaw = await env.VM_TENANT_DIRECTORY.get(`roles:${sub}`);
    if (!roleRaw) {
      await env.VM_TENANT_DIRECTORY.put(`roles:${sub}`, JSON.stringify({ role: 'operator' }));
      console.log(`[VoidMetric Auth] Provisioned role=operator for sub=${sub} (mode=${mode})`);
    }

    // Ensure tenantName record exists
    const nameRaw = await env.VM_TENANT_DIRECTORY.get(`tenantName:${tenantId}`);
    if (!nameRaw) {
      await env.VM_TENANT_DIRECTORY.put(`tenantName:${tenantId}`, tenantId);
    }

    // 10. Resolve role
    const role = await resolveRole(sub, env);

    // 11. Mint opaque session token (decoupled from IdP token lifetime)
    const sessionToken = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
    await env.VM_TENANT_DIRECTORY.put(`session:${sessionToken}`, JSON.stringify({
      sub,
      tenantId,
      role,
      email,
      createdAt: Date.now(),
    }), { expirationTtl: 86400 });

    const headers = new Headers();
    headers.set('Location', `/integrity-portal?tenant=${tenantId}`);
    headers.append('Set-Cookie', `aim_session_token=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
    headers.append('Set-Cookie', `auth_domain=${tenantId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
    clearFlowCookies(headers);

    console.log(`[VoidMetric Auth] ✅ Session established: sub=${sub} tenant=${tenantId} role=${role} mode=${mode}`);

    return new Response(null, { status: 302, headers });

  } catch (err) {
    console.error('[VoidMetric Auth] Unhandled error:', err);
    const resp = errorRedirect('internal_error');
    clearFlowCookies(resp.headers);
    return resp;
  }
};   