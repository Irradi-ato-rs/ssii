// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { env } from 'cloudflare:workers';
import { getIdPConfig } from '../../../config/tenants';   

export const GET: APIRoute = async ({ request, cookies, redirect }) => {
  try {
    const requestUrl = new URL(request.url);
    const code = requestUrl.searchParams.get('code');
    const state = requestUrl.searchParams.get('state');
    const error = requestUrl.searchParams.get('error');

    if (error) return redirect(`/login?error=${encodeURIComponent(error)}`);
    if (!code || !state) return redirect('/login?error=missing_params');

    // 1. STRICT CSRF COOKIE MATCHING (NO domain attribute allowed)
    const browserCookieVerification = cookies.get('__Host-auth_state_verification')?.value;
    if (!browserCookieVerification || browserCookieVerification !== state) {
      console.error('[VoidMetric Auth] State mismatch - possible CSRF');
      return redirect('/login?error=xsrf_state_mismatch');
    }

    // 2. IMMEDIATE STATE DELETION (Prevent Replay & Race Conditions)
    const storedPayload = await env.SESSION.get(`oidc_state:${state}`);
    if (!storedPayload) return redirect('/login?error=invalid_state');
    
    // Nuclear option: Delete state immediately before handling heavy crypto/fetches
    await env.SESSION.delete(`oidc_state:${state}`);

    // Parse the payload safely
    const { domain, email } = JSON.parse(storedPayload);

    // 3. SECURE ENV VARIABLE ACQUISITION GUARDRAIL
    const config = getIdPConfig(`user@${domain}`);
    if (!config) return redirect('/login?error=domain_not_found');

    const clientIdEnvKey = config.clientIdEnv;
    const clientSecretEnvKey = config.clientSecretEnv;
    if (!clientIdEnvKey.startsWith('OIDC_') || !clientSecretEnvKey.startsWith('OIDC_')) {
      return redirect('/login?error=system_violation');
    }

    const clientId = env[clientIdEnvKey]?.trim();
    const clientSecret = env[clientSecretEnvKey]?.trim();
    if (!clientId || !clientSecret) return redirect('/login?error=config_error');

    // 4. PRECISE METHOD TOKEN EXCHANGE (No Magic Fallbacks)
    const rigidCallbackString = "https://ssii.fzoirm.com/api/auth/callback";
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const bodyParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: rigidCallbackString
    });

    if (config.authMethod === 'client_secret_post') {
      bodyParams.set('client_id', clientId);
      bodyParams.set('client_secret', clientSecret);
    } else {
      headers['Authorization'] = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    }

    const tokenResponse = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers,
      body: bodyParams
    });

    if (!tokenResponse.ok) return redirect('/login?error=token_exchange_failed');

    const tokenData = await tokenResponse.json();
    const idToken = tokenData.id_token;
    if (!idToken) return redirect('/login?error=no_id_token');

    // 5. CRYPTOGRAPHIC INTEGRITY VERIFICATION
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    const { payload } = await jwtVerify(idToken, JWKS, {
      issuer: config.issuer,
      audience: clientId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: 60
    });

    // Verify parsed token email matches the session initialization email
    if (payload.email && String(payload.email).toLowerCase() !== email.toLowerCase()) {
      return redirect('/login?error=identity_mismatch');
    }

    // 6. DEPLOY AUTHORITATIVE RUNTIME SESSION
    const sessionId = crypto.randomUUID();
    await env.SESSION.put(`session:${sessionId}`, JSON.stringify({
      email,
      createdAt: Date.now(),
    }), { expirationTtl: 3600 });

    // 7. COMPLIANT RESPONSE CLEANUP & REDIRECT
    // CRITICAL: DO NOT add 'domain' attribute to __Host- cookie deletion
    cookies.delete('__Host-auth_state_verification', { path: '/' });
    
    cookies.set('session', sessionId, {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 3600
    });

    return redirect('/integrity-portal');

  } catch (error) {
    // OPTIMIZATION: Log error details for production debugging
    console.error('[VoidMetric Auth] Critical Failure:', error);
    return redirect('/login?error=internal_error');
  }
};   