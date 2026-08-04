// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfig } from '../../config/tenants'; // Import helper

export const GET: APIRoute = async ({ request, url }) => {
  try {
    const searchParams = new URL(request.url).searchParams;
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

    // 1. Validate & Decode State
    const cookies = request.headers.get('Cookie') || '';
    const stateCookie = cookies.split(';').find(c => c.trim().startsWith('oidc_state='))?.split('=')[1];
    
    if (!stateCookie || stateCookie !== state) {
      console.error('State Mismatch:', { cookie: stateCookie, param: state });
      return new Response('Invalid state parameter', { status: 403 });
    }

    let domain;
    try {
      // Decode Base64 state to get domain
      const decoded = JSON.parse(atob(state));
      domain = decoded.domain;
    } catch (e) {
      console.error('Failed to decode state:', e);
      return new Response('Invalid state format', { status: 400 });
    }

    // 2. Get Tenant Config based on decoded domain
    // We create a mock email to use our existing helper
    const config = getIdPConfig(`user@${domain}`);
    
    if (!config) {
      console.error('Unknown domain:', domain);
      return new Response('Domain configuration not found', { status: 500 });
    }

    // 3. Resolve Secrets
    const clientId = env[config.clientIdEnv];
    const clientSecret = env[config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      console.error('Missing secrets for domain:', domain);
      return new Response('Configuration error', { status: 500 });
    }

    // 4. Exchange Code for Token
    const tokenResponse = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: `${url.origin}/api/auth/callback`,
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

    // 5. Verify ID Token Signature
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

    // 6. Set Secure Session Cookie
    const headers = new Headers();
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    headers.append('Location', '/integrity-portal');
    
    return new Response(null, { status: 302, headers });

  } catch (error) {
    console.error('Callback Error:', error);
    return new Response(`Internal Server Error: ${error}`, { status: 500 });
  }
};   