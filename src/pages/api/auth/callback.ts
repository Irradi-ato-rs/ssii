// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfig } from '../../../config/tenants';   

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

export const GET: APIRoute = async (context) => {
  const { request, cookies, locals } = context;
  
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

    // 1. Validate State Cookie (CSRF Protection)
    const stateCookie = cookies.get('oidc_state');
    if (!stateCookie || stateCookie.value !== state) {
      console.error('[VoidMetric Auth] State mismatch');
      return new Response('Invalid state', { status: 403 });
    }

    // 2. Decode Domain & Nonce from State
    let domain: string;
    let stateNonceCheck = "";
    
    try {
      let base64Payload = state.replace(/-/g, '+').replace(/_/g, '/');
      while (base64Payload.length % 4) {
        base64Payload += '=';
      }
      const decoded = JSON.parse(atob(base64Payload));
      domain = decoded.domain;
      stateNonceCheck = decoded.nonce || "";
    } catch (e) {
      return new Response('Invalid state format', { status: 400 });
    }

    // 3. Get Tenant Config
    const config = getIdPConfig(`user@${domain}`) as DynamicIdPConfig;
    if (!config) {
      return new Response('Domain not found', { status: 500 });
    }

    // 4. Access Secrets
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env || {};
    const clientId = runtimeEnv[config.clientIdEnv]?.trim();
    const clientSecret = runtimeEnv[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error(`MISSING SECRETS: ${config.clientIdEnv} or ${config.clientSecretEnv}`);
      return new Response('Missing Credentials', { status: 500 });
    }

    // 5. Token Exchange
    // CRITICAL FIX: Must match Azure Portal Redirect URI exactly
    const rigidCallbackString = "https://ssii.fzoirm.com/api/auth/callback";
    
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
          redirect_uri: rigidCallbackString
        })
      });
      
      // Fallback to POST if Basic fails
      if (!tokenResponse.ok) {
        tokenResponse = await fetch(config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: rigidCallbackString,
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
          redirect_uri: rigidCallbackString,
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

    // 6. Verify Token Signatures & Secure Core Claims
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    
    // Hard check validation matrix: Enforces that the ID Token was generated specifically for THIS login sequence
    await jwtVerify(idToken, JWKS, {
      issuer: config.issuer,
      audience: clientId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '60s',
      // CRITICAL LAYER: Token validation matching requirement (Prevents Replay Attacks)
      ...(stateNonceCheck ? { nonce: stateNonceCheck } : {})
    });

    // 7. Set Cookies & Redirect
    const headers = new Headers();
    // Clear state cookie
    headers.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    // Set session token (1 hour expiry)
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    // Redirect to dashboard
    headers.append('Location', '/integrity-portal');

    return new Response(null, { status: 302, headers });   

  } catch (error) {
    console.error('[VoidMetric Auth] Crash:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
};   