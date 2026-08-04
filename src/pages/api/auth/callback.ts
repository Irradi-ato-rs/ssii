// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose'; // Edge-native cryptographic verification
import { env } from 'cloudflare:workers'; // Astro 6 Fix: Direct import

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

export const GET: APIRoute = async (context) => {
  const { request } = context;
  // Astro 6 Fix: Access KV/Secrets via imported 'env', not locals.runtime
  const tenantDirectory = env.VM_TENANT_DIRECTORY; 

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

    // 1. Validate State Parameter Matrix
    const cookies = request.headers.get('Cookie') || '';
    const stateCookieValue = cookies
      .split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('oidc_state='))
      ?.split('=')[1];
    
    if (!stateCookieValue || stateCookieValue !== state) {
      console.error('State Mismatch Error');
      return new Response('Invalid state parameter', { status: 403 });
    }

    let domain: string;
    try {
      const decodedPayloadStr = atob(state);
      const decoded = JSON.parse(decodedPayloadStr);
      domain = decoded.domain;
    } catch (e) {
      console.error('Failed to decode state:', e);
      return new Response('Invalid state format', { status: 400 });
    }

    // 2. Resolve Tenant Config from KV
    if (!tenantDirectory) {
      console.error('VM_TENANT_DIRECTORY binding missing');
      return new Response('Infrastructure routing failure', { status: 500 });
    }

    const tenantConfigRaw = await tenantDirectory.get(`domain:${domain}`);
    if (!tenantConfigRaw) {
      console.error('Unknown domain:', domain);
      return new Response('Domain configuration not found', { status: 500 });
    }
    const config = JSON.parse(tenantConfigRaw) as DynamicIdPConfig;

    // 3. Resolve Secrets from Imported Env
    const clientId = env[config.clientIdEnv]?.trim();
    const clientSecret = env[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error('Missing secrets for:', domain);
      return new Response('Configuration error', { status: 500 });
    }

    // 4. Resolve Canonical Origin
    const host = request.headers.get('host') || requestUrl.host;
    const protocol = request.headers.get('x-forwarded-proto') || 'https';
    const origin = `${protocol}://${host}`;

    // 5. Token Exchange (Basic Auth)
    const headers = new Headers();
    const bodyParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: `${origin}/api/auth/callback`
    });

    const preference = config.authMethod || 'client_secret_basic';

    if (preference === 'client_secret_basic') {
      const secureHeaderCredentials = btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`);
      headers.set('Authorization', `Basic ${secureHeaderCredentials}`);
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
    } else {
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
      bodyParams.append('client_id', clientId);
      bodyParams.append('client_secret', clientSecret);
    }

    const tokenResponse = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers,
      body: bodyParams
    });

    if (!tokenResponse.ok) {
      const errText = await tokenResponse.text();
      console.error('Token Exchange Failed:', errText);
      return new Response(`Token exchange failed: ${errText}`, { status: 401 });
    }

    const tokenData = await tokenResponse.json() as { id_token?: string };
    const idToken = tokenData.id_token;

    if (!idToken) {
      return new Response('No ID Token received', { status: 500 });
    }

    // 6. Verify ID Token Signature using JWKS (Asymmetric)
    // FIX: Use jose + JWKS instead of symmetric iclassed verifyJwt
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    
    try {
      await jwtVerify(idToken, JWKS, {
        issuer: config.issuer,
        audience: clientId,
        algorithms: ['RS256', 'RS384', 'RS512'], // Entra ID standard
      });
    } catch (err) {
      console.error('JWT Verification Failed:', err);
      return new Response('Invalid Token Signature', { status: 403 });
    }

    // 7. Set Session Cookie
    const responseHeaders = new Headers();
    responseHeaders.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    responseHeaders.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    responseHeaders.append('Location', '/integrity-portal');
    
    return new Response(null, { status: 302, headers: responseHeaders });

  } catch (error) {
    console.error('Callback Error:', error);
    return new Response(`Internal Server Error`, { status: 500 });
  }
};   