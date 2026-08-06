// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { env } from 'cloudflare:workers';
// FIX: Static import at the top
//import { getIdPConfig } from '../../config/tenants';
import { getIdPConfig } from '../../../config/tenants';   

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

export const GET: APIRoute = async ({ request, cookies }) => {
  try {
    const requestUrl = new URL(request.url);
    const code = requestUrl.searchParams.get('code');
    const state = requestUrl.searchParams.get('state');
    const error = requestUrl.searchParams.get('error');

    if (error) {
      console.error('[VoidMetric Auth] IdP Error:', error);
      return new Response(`Authentication failed: ${error}`, { status: 403 });
    }

    if (!code || !state) {
      return new Response('Missing code or state', { status: 400 });
    }

    // 1. Validate State
    const stateCookie = cookies.get('oidc_state');
    if (!stateCookie || stateCookie.value !== state) {
      console.error('[VoidMetric Auth] State mismatch');
      return new Response('Invalid state', { status: 403 });
    }

    // Decode Domain
    let domain: string;
    try {
      const decoded = JSON.parse(atob(state));
      domain = decoded.domain;
    } catch (e) {
      return new Response('Invalid state format', { status: 400 });
    }

    // 2. Get Tenant Config
    // Mock an email to pass to getIdPConfig (it only uses the domain part)
    const config = getIdPConfig(`user@${domain}`);

    if (!config) {
      return new Response('Domain not found', { status: 500 });
    }

    // 3. Access Secrets
    const clientId = env[config.clientIdEnv];
    const clientSecret = env[config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      console.error(`MISSING SECRETS: ${config.clientIdEnv} or ${config.clientSecretEnv}`);
      return new Response('Missing Credentials', { status: 500 });
    }

    // 4. Token Exchange
    const SITE_URL = env.SITE_URL || "https://ssii.fzoirm.com";
    const redirectUri = `${SITE_URL}/api/auth/callback`;

    let tokenResponse;
    const useBasicAuth = config.authMethod !== 'client_secret_post';

    if (useBasicAuth) {
      const encoded = btoa(`${clientId}:${clientSecret}`);
      tokenResponse = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${encoded}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri
        })
      });
      
      if (!tokenResponse.ok) {
        tokenResponse = await fetch(config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: clientId,
            client_secret: clientSecret
          })
        });
      }
    } else {
      tokenResponse = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          client_secret: clientSecret
        })
      });
    }

    if (!tokenResponse.ok) {
      const err = await tokenResponse.text();
      console.error('Token Exchange Failed:', err);
      return new Response(`Token Failed: ${err}`, { status: 401 });
    }

    const tokenData = await tokenResponse.json();
    const idToken = tokenData.id_token;

    if (!idToken) return new Response('No ID Token', { status: 500 });

    // 5. Verify Token
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    await jwtVerify(idToken, JWKS, {
      issuer: config.issuer,
      audience: clientId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '60s'
    });

    // 6. Set Cookies & Redirect
    const headers = new Headers();
    headers.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    headers.append('Location', '/integrity-portal');

    return new Response(null, { status: 302, headers });   

  } catch (error) {
    console.error('[VoidMetric Auth] Crash:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
};   