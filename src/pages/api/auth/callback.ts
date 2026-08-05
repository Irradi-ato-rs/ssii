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
    const searchParams = requestUrl.searchParams;
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');

    if (error) {
      console.error('[VoidMetric Auth] Error payload returned from IdP:', error);
      return new Response(`Authentication failed: ${error}`, { status: 403 });
    }

    if (!code || !state) {
      return new Response('Missing code or state parameters', { status: 400 });
    }

    // 1. Validate State Parameter Matrix
    const stateCookie = cookies.get('oidc_state');
    if (!stateCookie || stateCookie.value !== state) {
      console.error('[VoidMetric Auth] Critical State parameter discrepancy encountered.');
      return new Response('Invalid state parameter mapping', { status: 403 });
    }

    let domain: string;
    try {
      const decodedPayloadStr = atob(state);
      const decoded = JSON.parse(decodedPayloadStr);
      domain = decoded.domain;
    } catch (e) {
      console.error('[VoidMetric Auth] Base64 string expansion failure:', e);
      return new Response('Invalid state format template', { status: 400 });
    }

    // 2. Extract Tenant Context Dynamically from KV
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY; 
    
    if (!tenantDirectory) {
      console.error('[VoidMetric Auth] Bound Cloudflare Resource VM_TENANT_DIRECTORY Unreached');
      return new Response('Infrastructure environment routing failure', { status: 500 });
    }

    const tenantConfigRaw = await tenantDirectory.get(`domain:${domain}`);
    if (!tenantConfigRaw) {
      console.error(`[VoidMetric Auth] Tenant profile registration missing for: ${domain}`);
      return new Response('Domain configuration mapping index not found', { status: 500 });
    }
    const config = JSON.parse(tenantConfigRaw) as DynamicIdPConfig;

    // 3. Extract Environmental Credentials
    const clientId = runtimeEnv?.[config.clientIdEnv]?.trim();
    const clientSecret = runtimeEnv?.[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error(`[VoidMetric Auth] Key registration unpopulated inside environmental space for: ${domain}`);
      return new Response('Infrastructure environment credential configuration error', { status: 500 });
    }

    // 4. Resolve True Canonical Origin
    const host = request.headers.get('host') || requestUrl.host;
    const protocol = request.headers.get('x-forwarded-proto') || 'https';
    const origin = `${protocol}://${host}`;
    const redirectUri = `${origin}/api/auth/callback`;

    // 5. Token Exchange (With URL Encoding Fix & Fallback)
    let tokenResponse;
    const preference = config.authMethod || 'client_secret_basic';

    if (preference === 'client_secret_basic') {
      // FIX: URL-encode credentials BEFORE Base64 encoding per RFC 6749
      const encodedId = encodeURIComponent(clientId);
      const encodedSecret = encodeURIComponent(clientSecret);
      const base64BasicToken = btoa(`${encodedId}:${encodedSecret}`);
      
      tokenResponse = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${base64BasicToken}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: redirectUri
        })
      });

      // Fallback Strategy B if Basic Auth fails
      if (!tokenResponse.ok) {
        const errorCheckText = await tokenResponse.clone().text();
        if (errorCheckText.includes('invalid_client')) {
          console.warn('[VoidMetric Auth] Basic Auth rejected. Executing Strategy B (Form Parameters)...');
          
          tokenResponse = await fetch(config.tokenEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              code: code,
              redirect_uri: redirectUri,
              client_id: clientId,
              client_secret: clientSecret
            })
          });
        }
      }
    } else {
      tokenResponse = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: redirectUri,
          client_id: clientId,
          client_secret: clientSecret
        })
      });
    }

    if (!tokenResponse.ok) {
      const ultimateFailureLogText = await tokenResponse.text();
      console.error('[VoidMetric Auth Fatal] Token exchange rejected completely:', ultimateFailureLogText);
      return new Response(`Token exchange failed: ${ultimateFailureLogText}`, { status: 401 });
    }

    const tokenData = await tokenResponse.json() as { id_token?: string };
    const idToken = tokenData.id_token;

    if (!idToken) {
      return new Response('Identity verification rejected: ID Token missing', { status: 500 });
    }

    // 6. Asymmetric JWKS Signature Verification
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    try {
      await jwtVerify(idToken, JWKS, {
        issuer: config.issuer,
        audience: clientId,
        algorithms: ['RS256', 'RS384', 'RS512'],
        clockTolerance: '60s'
      });
    } catch (err) {
      console.error('[VoidMetric Auth Fatal] Signature check mismatch:', err);
      return new Response('Invalid Identity Token Signature', { status: 403 });
    }

    // 7. FIX: Manual Set-Cookie Headers (Critical for Cloudflare Redirects)
        // 7. FIX: Manual Set-Cookie Headers (Atomic Redirect)
    const responseHeaders = new Headers();

    // A. Clear the state cookie
    responseHeaders.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');

    // B. Set the session token cookie (CRITICAL: Must be same response as Location)
    responseHeaders.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);

    // C. Redirect to your dashboard
    responseHeaders.append('Location', '/integrity-portal');

    return new Response(null, { 
      status: 302, 
      headers: responseHeaders 
    });   