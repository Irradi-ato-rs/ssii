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

    // 1. Validate State Parameter Matrix against session context cookies
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

    // 2. Extract Tenant Context Dynamically from Secure KV Storage Vault
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env;
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

    // 3. Extract Environmental Credentials from correct Request Context Array
    const clientId = runtimeEnv?.[config.clientIdEnv]?.trim();
    const clientSecret = runtimeEnv?.[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error(`[VoidMetric Auth] Key registration unpopulated inside environmental space for: ${domain}`);
      return new Response('Infrastructure environment credential configuration error', { status: 500 });
    }

    // 4. Resolve True Canonical Origin Redirect Parameters
    const host = request.headers.get('host') || requestUrl.host;
    const protocol = request.headers.get('x-forwarded-proto') || 'https';
    const origin = `${protocol}://${host}`;
    const redirectUri = `${origin}/api/auth/callback`;

    // 5. STEPPED AUTOMATED RECOVERY HANDSHAKE PIPELINE
    let tokenResponse;
    const preference = config.authMethod || 'client_secret_basic';

    if (preference === 'client_secret_basic') {
      const rawCredentialsString = `${clientId}:${clientSecret}`;
      const base64BasicToken = btoa(rawCredentialsString);
      
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

      if (!tokenResponse.ok) {
        const errorCheckText = await tokenResponse.clone().text();
        if (errorCheckText.includes('invalid_client')) {
          console.warn('[VoidMetric Auth] Basic Auth rejected with invalid_client. Executing Strategy B Form Parameters inject...');
          
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
      console.error('[VoidMetric Auth Fatal] Token exchange rejected completely across all pipelines:', ultimateFailureLogText);
      return new Response(`Token exchange failed: ${ultimateFailureLogText}`, { status: 401 });
    }

    const tokenData = await tokenResponse.json() as { id_token?: string };
    const idToken = tokenData.id_token;

    if (!idToken) {
      return new Response('Identity verification rejected: ID Token missing from server response payload', { status: 500 });
    }

    // 6. Asymmetric JWKS Public-Key Signature Verification Loop
    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    try {
      await jwtVerify(idToken, JWKS, {
        issuer: config.issuer,
        audience: clientId,
        algorithms: ['RS256', 'RS384', 'RS512'],
        clockTolerance: '60s'
      });
    } catch (err) {
      console.error('[VoidMetric Auth Fatal] Asymmetric token profile signature check mismatch:', err);
      return new Response('Invalid Identity Token Signature Integrity Check Failed', { status: 403 });
    }

    // 7. Clear transient parameters state cookies and dispatch authorized session token
    cookies.delete('oidc_state', { path: '/' });
    cookies.set('aim_session_token', idToken, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 3600
    });

    const responseHeaders = new Headers();
    responseHeaders.append('Location', '/integrity-portal');
    return new Response(null, { status: 302, headers: responseHeaders });

  } catch (error) {
    console.error('[VoidMetric Auth Exception] Crash caught inside callback execution channel:', error);
    return new Response(`Internal Server Error`, { status: 500 });
  }
};
