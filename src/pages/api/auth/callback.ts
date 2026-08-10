// src/pages/api/auth/callback.ts
export const prerender = false;

import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers'; // REQUIRED for Astro 6
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

// Module-level cache: one JWKS fetcher per jwksUri
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
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

export const GET: APIRoute = async ({ request, cookies }) => { // Removed 'locals'
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

    // 3. Decode domain & nonce from state
    let domain: string;
    let stateNonce = '';
    try {
      let base64Payload = state.replace(/-/g, '+').replace(/_/g, '/');
      while (base64Payload.length % 4) base64Payload += '=';
      const decoded = JSON.parse(atob(base64Payload));
      domain = decoded.domain;
      stateNonce = decoded.nonce || '';
    } catch {
      return errorRedirect('invalid_state');
    }

    // 4. Get tenant config from KV (PASS env)
    const config = await getIdPConfigByDomain(env, domain); // Changed
    if (!config) {
      console.error(`[VoidMetric Auth] No IdP config for domain=${domain}`);
      return errorRedirect('tenant_access_denied');
    }

    // 5. Access secrets from imported env (NOT locals.runtime)
    const clientId = env[config.clientIdEnv]?.trim(); // Changed
    const clientSecret = env[config.clientSecretEnv]?.trim(); // Changed

    if (!clientId || !clientSecret) {
      console.error(`[VoidMetric Auth] Missing secret for domain=${domain}`);
      return errorRedirect('signin_unavailable');
    }

    // 6. Token exchange (with PKCE code_verifier included)
    const rigidCallbackString = 'https://ssii.fzoirm.com/api/auth/callback';
    const useBasicAuth = config.authMethod !== 'client_secret_post';

    async function exchangeWithBasicAuth() {
      const encoded = btoa(`${clientId}:${clientSecret}`);
      return fetch(config.tokenEndpoint, {
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
      });
    }

    async function exchangeWithClientSecretPost() {
      return fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: rigidCallbackString,
          client_id: clientId,
          client_secret: clientSecret,
          code_verifier: codeVerifier,
        }),
      });
    }

    let tokenResponse = useBasicAuth ? await exchangeWithBasicAuth() : await exchangeWithClientSecretPost();

    if (!tokenResponse.ok && useBasicAuth) {
      const firstAttemptError = await tokenResponse.text();
      console.error('[VoidMetric Auth] Basic auth token exchange failed, retrying with client_secret_post:', firstAttemptError);
      tokenResponse = await exchangeWithClientSecretPost();
    }

    if (!tokenResponse.ok) {
      const err = await tokenResponse.text();
      console.error('[VoidMetric Auth] Token exchange failed:', err);
      return errorRedirect('handshake_failed');
    }

    const tokenData = await tokenResponse.json();
    const idToken = tokenData.id_token;

    if (!idToken) {
      console.error('[VoidMetric Auth] No id_token in token response');
      return errorRedirect('handshake_failed');
    }

    // 7. Verify token signature & claims
    const JWKS = getJwks(config.jwksUri);

    let exp: number | undefined;
    try {
      const { payload } = await jwtVerify(idToken, JWKS, {
        issuer: config.issuer,
        audience: clientId,
        algorithms: ['RS256', 'RS384', 'RS512'],
        clockTolerance: '60s',
        ...(stateNonce ? { nonce: stateNonce } : {}),
      });
      exp = payload.exp;
    } catch (verifyErr) {
      console.error('[VoidMetric Auth] ID token verification failed:', verifyErr);
      return errorRedirect('handshake_failed');
    }

    // 8. Derive session cookie lifetime
    const nowSeconds = Math.floor(Date.now() / 1000);
    const DEFAULT_MAX_AGE = 3600;
    const MIN_MAX_AGE = 60;
    const sessionMaxAge = exp
      ? Math.max(MIN_MAX_AGE, exp - nowSeconds)
      : DEFAULT_MAX_AGE;

    // 9. Set session cookies, clear flow cookies, redirect
    const headers = new Headers();
    clearFlowCookies(headers);
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${sessionMaxAge}`);
    headers.append('Set-Cookie', `auth_domain=${domain}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${sessionMaxAge}`);
    headers.append('Location', '/integrity-portal');

    return new Response(null, { status: 302, headers });
  } catch (err) {
    console.error('[VoidMetric Auth] Crash:', err);
    return errorRedirect('handshake_failed');
  }
};   