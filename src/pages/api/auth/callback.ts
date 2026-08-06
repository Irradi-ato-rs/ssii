// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

export const GET: APIRoute = async (context) => {
  const { request, locals, cookies } = context;
  
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
      // FIX: Ensure proper decoding if state was URI encoded
      const decoded = JSON.parse(atob(state));
      domain = decoded.domain;
    } catch (e) {
      return new Response('Invalid state format', { status: 400 });
    }

    // 2. Get Tenant Config
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY; 
    
    if (!tenantDirectory) {
      return new Response('KV Binding Missing', { status: 500 });
    }

    // FIX: Handle fzoirm.com host override if not in KV
    let tenantConfigRaw = await tenantDirectory.get(`domain:${domain}`);
    
    // If not found and it's the host domain, use hardcoded config (Optional safety net)
    if (!tenantConfigRaw && domain === 'fzoirm.com') {
       // You can implement the hardcoded logic here if you didn't update tenants.ts
       // For now, assuming tenants.ts or KV has it.
       return new Response('Host domain not configured', { status: 500 });
    }

    if (!tenantConfigRaw) {
      return new Response('Domain not found', { status: 500 });
    }

    const config = JSON.parse(tenantConfigRaw) as DynamicIdPConfig;

    const clientId = runtimeEnv?.[config.clientIdEnv]?.trim();
    const clientSecret = runtimeEnv?.[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      return new Response('Missing Credentials', { status: 500 });
    }

    // 3. Token Exchange / Hardcode and force production domain / check iclassed BIC
    //const host = request.headers.get('host') || requestUrl.host;
    //const protocol = request.headers.get('x-forwarded-proto') || 'https';
    //const redirectUri = `${protocol}://${host}/api/auth/callback`;
    //const SITE_URL = locals.runtime?.env?.SITE_URL || "https://ssii.fzoirm.com";
    //const redirectUri = `${SITE_URL}/api/auth/callback`;
    const SITE_URL = "https://ssii.fzoirm.com"; // Or from env: locals.runtime.env.SITE_URL
    const redirectUri = `${SITE_URL}/api/auth/callback`;   

    let tokenResponse;
    const useBasicAuth = config.authMethod !== 'client_secret_post';

    if (useBasicAuth) {
      // FIX: Standard Basic Auth encoding
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
      
      // Fallback if Basic fails
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
    const idToken = tokenData.id_token; // FIX: Correct variable name

    if (!idToken) return new Response('No ID Token', { status: 500 });

    // 4. Verify Token
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    await jwtVerify(idToken, JWKS, {
      issuer: config.issuer,
      audience: clientId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '60s'
    });

    // 5. Set Cookies & Redirect
    const headers = new Headers();
    
    // Clear State
    headers.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    
    // Set Session Token
    // FIX: Ensure 'Secure' is only used on HTTPS. Cloudflare Pages is always HTTPS in prod.
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    
    // Redirect to Dashboard
    headers.append('Location', '/integrity-portal');

    console.log('=== CALLBACK SUCCESS ===');
    console.log('Redirecting to:', '/integrity-portal');

    return new Response(null, { status: 302, headers });   

  } catch (error) {
    console.error('[VoidMetric Auth] Crash:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
};   