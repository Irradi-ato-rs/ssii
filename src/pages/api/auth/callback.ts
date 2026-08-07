export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { env } from 'cloudflare:workers'; // Direct Astro 6 edge runtime variable injection
import { getIdPConfig } from '../../../config/tenants';   

export const GET: APIRoute = async (context) => {
  const { request, cookies, redirect } = context;

  try {
    const requestUrl = new URL(request.url);
    const code = requestUrl.searchParams.get('code');
    const state = requestUrl.searchParams.get('state');
    const error = requestUrl.searchParams.get('error');

    if (error) return redirect(`/login?error=${encodeURIComponent(error)}`, 303);
    if (!code || !state) return redirect('/login?error=missing_params', 303);

    // 1. Strict XSRF State Cookie Matching (The Cryptographic Anchor)
    const browserCookieVerification = cookies.get('__Host-auth_state_verification')?.value;
    if (!browserCookieVerification || browserCookieVerification !== state) {
      return redirect('/login?error=xsrf_state_mismatch', 303);
    }

    // 2. Race Condition Isolation (Atomic Cache Deletion Loop)
    const storedPayload = await env.SESSION.get(`oidc_state:${state}`);
    if (!storedPayload) return redirect('/login?error=invalid_state', 303);
    
    // Purge entry transaction instantly before running remote requests to isolate replays
    await env.SESSION.delete(`oidc_state:${state}`);
    cookies.delete('__Host-auth_state_verification', { path: '/' });

    const { domain, email } = JSON.parse(storedPayload);

    // 3. Secured Tenant Environment Mapping Checks
    const config = getIdPConfig(`user@${domain}`);
    if (!config) return redirect('/login?error=domain_not_found', 303);

    const clientIdEnvKey = config.clientIdEnv;
    const clientSecretEnvKey = config.clientSecretEnv;
    if (!clientIdEnvKey.startsWith('PRIVATE_ENTRA_') || !clientSecretEnvKey.startsWith('PRIVATE_ENTRA_')) {
      return redirect('/login?error=system_violation', 303);
    }

    const clientId = env[clientIdEnvKey]?.trim();
    const clientSecret = env[clientSecretEnvKey]?.trim();
    if (!clientId || !clientSecret) return redirect('/login?error=config_error', 303);

    // 4. Token Exchange Flow Configuration (No Dangerous Magic Fallbacks)
    const rigidCallbackString = "https://fzoirm.com";
    const requestHeaders: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const bodyParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: rigidCallbackString
    });

    if (config.authMethod === 'client_secret_post') {
      bodyParams.set('client_id', clientId);
      bodyParams.set('client_secret', clientSecret);
    } else {
      requestHeaders['Authorization'] = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    }

    const tokenResponse = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: requestHeaders,
      body: bodyParams
    });

    if (!tokenResponse.ok) return redirect('/login?error=token_exchange_failed', 303);

    const tokenData = await tokenResponse.json();
    const idToken = tokenData.id_token;
    if (!idToken) return redirect('/login?error=no_id_token', 303);

    // 5. Cryptographic Signature Validation
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    const { payload } = await jwtVerify(idToken, JWKS, {
      issuer: config.issuer,
      audience: clientId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: 60
    });

    // Identity Mapping Cross-Validation Protection
    if (payload.email && String(payload.email).toLowerCase() !== email.toLowerCase()) {
      return redirect('/login?error=identity_mismatch', 303);
    }

    // 6. Deploy Ephemeral Production Edge Session Identity
    const sessionId = crypto.randomUUID();
    await env.SESSION.put(`session:${sessionId}`, JSON.stringify({
      email,
      createdAt: Date.now(),
    }), { expirationTtl: 3600 });

    // Set production tracking cookie session token
    cookies.set('aim_session_token', sessionId, {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax', // Lax is required to preserve user state after standard redirects
      maxAge: 3600
    });

    return redirect('/integrity-portal', 302);

  } catch (error) {
    return redirect('/login?error=internal_callback_error', 303);
  }
};
