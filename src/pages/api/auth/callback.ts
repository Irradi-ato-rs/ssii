// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfig } from '../../../config/tenants';

export const GET: APIRoute = async ({ request }) => {
  try {
    const requestUrl = new URL(request.url);
    const searchParams = requestUrl.searchParams;
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');

    if (error) {
      console.error('Auth Error from IdP:', error);
      return new Response(`Authentication failed: ${error}`, { status: 403 });
    }

    if (!code || !state) {
      return new Response('Missing code or state', { status: 400 });
    }

    // 1. Validate & Decode State Safely
    // FIX: Enhanced split parsing to defend against multi-cookie trailing spaces
    const cookies = request.headers.get('Cookie') || '';
    const stateCookie = cookies
      .split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('oidc_state='))
      ?.split('=')[1];
    
    if (!stateCookie || stateCookie !== state) {
      console.error('State Mismatch:', { cookie: stateCookie, param: state });
      return new Response('Invalid state parameter', { status: 403 });
    }

    let domain;
    try {
      // FIX: Replaced atob with edge-safe buffer decoding to maintain unicode string safety
      const decodedPayloadStr = Buffer.from(state, 'base64').toString('utf-8');
      const decoded = JSON.parse(decodedPayloadStr);
      domain = decoded.domain;
    } catch (e) {
      console.error('Failed to decode state:', e);
      return new Response('Invalid state format', { status: 400 });
    }

    // 2. Resolve Tenant Configuration Boundaries
    const config = getIdPConfig(`user@${domain}`);
    if (!config) {
      console.error('Unknown domain:', domain);
      return new Response('Domain configuration not found', { status: 500 });
    }

    // 3. Resolve Environmental Secrets from Global V8 Context Object
    // FIX: Bypassed clashing cloudflare worker module imports
    const globalContext = globalThis as any;
    const clientId = globalContext.process?.env?.[config.clientIdEnv] || globalContext[config.clientIdEnv];
    const clientSecret = globalContext.process?.env?.[config.clientSecretEnv] || globalContext[config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      console.error('Missing secrets for domain:', domain);
      return new Response('Configuration error', { status: 500 });
    }

    // 4. Resolve True Canonical Origin Redirect Path
    const host = request.headers.get('host') || requestUrl.host;
    const protocol = request.headers.get('x-forwarded-proto') || 'https';
    const origin = `${protocol}://${host}`;

    // 5. Exchange Authorization Code for JWT Identity Tokens
    const tokenResponse = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: `${origin}/api/auth/callback`,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });

    if (!tokenResponse.ok) {
      const errText = await tokenResponse.text();
      console.error('Token Exchange Failed:', errText);
      return new Response(`Token exchange failed: ${errText}`, { status: 401 });
    }

    const data = await tokenResponse.json();
    const idToken = data.id_token;

    if (!idToken) {
      return new Response('No ID Token received', { status: 500 });
    }

    // 6. Verify Third-Party ID Token Signature Remotely
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    try {
      await jwtVerify(idToken, JWKS, {
        issuer: config.issuer,
        audience: clientId,
      });
    } catch (err) {
      console.error('JWT Verification Failed:', err);
      return new Response('Invalid Token Signature', { status: 403 });
    }

    // 7. Clear State & Set Secure Session Token
    const headers = new Headers();
    // Flush the old single-use state verification cookie out of browser storage
    headers.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    // Commit the authentic session payload to secure cookie lanes
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    headers.append('Location', '/integrity-portal');
    
    return new Response(null, { status: 302, headers });

  } catch (error) {
    console.error('Callback Error:', error);
    return new Response(`Internal Server Error`, { status: 500 });
  }
};
