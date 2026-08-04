// src/pages/api/auth/callback.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { jwtVerify, createRemoteJWKSet } from 'jose';

export const GET: APIRoute = async ({ request, url }) => {
  try {
    const searchParams = new URL(request.url).searchParams;
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');

    if (error) {
      console.error('Auth Error from IdP:', error);
      return new Response('Authentication failed', { status: 403 });
    }

    if (!code || !state) {
      return new Response('Missing code or state', { status: 400 });
    }

    // 1. Validate State (CSRF Protection)
    // In a stateless arch, we rely on the cookie set in register.ts
    const cookies = request.headers.get('Cookie') || '';
    const stateCookie = cookies.split(';').find(c => c.trim().startsWith('oidc_state='))?.split('=')[1];
    
    if (!stateCookie || stateCookie !== state) {
      return new Response('Invalid state parameter', { status: 403 });
    }

    // 2. Determine Tenant (We need to know which config to use)
    // Since we don't have the email yet, we might need to try all or store domain in state.
    // Simplified: We assume single tenant or pass 'domain' in state during register.
    // For this example, we assume the 'state' contained the domain or we try the primary one.
    // BETTER: In register.ts, we should have encoded the domain in the 'state' param.
    // Let's assume we can retrieve the config. For now, we'll fetch the primary Entra config.
    // NOTE: In a multi-tenant app, you MUST encode the tenant ID in the 'state' param in register.ts.
    
    // Hardcoded lookup for demo (Replace with dynamic lookup based on state)
    const tenantConfig = {
      tokenEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/token",
      jwksUri: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/discovery/v2.0/keys",
      issuer: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/v2.0",
      clientId: env.PRIVATE_ENTRA_ICLASSED_CLIENT_ID,
      clientSecret: env.PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET,
      redirectUri: `${url.origin}/api/auth/callback`
    };

    if (!tenantConfig.clientId || !tenantConfig.clientSecret) {
      throw new Error('Missing Client ID or Secret in env');
    }

    // 3. Exchange Code for Token
    const tokenResponse = await fetch(tenantConfig.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: tenantConfig.redirectUri,
        client_id: tenantConfig.clientId,
        client_secret: tenantConfig.clientSecret,
      }),
    });

    if (!tokenResponse.ok) {
      const errText = await tokenResponse.text();
      console.error('Token Exchange Failed:', errText);
      return new Response('Failed to exchange code for token', { status: 401 });
    }

    const data = await tokenResponse.json();
    const idToken = data.id_token;

    if (!idToken) {
      return new Response('No ID Token received', { status: 500 });
    }

    // 4. Verify ID Token Signature (Cryptographic Check)
    const JWKS = createRemoteJWKSet(new URL(tenantConfig.jwksUri));
    try {
      await jwtVerify(idToken, JWKS, {
        issuer: tenantConfig.issuer,
        audience: tenantConfig.clientId,
      });
    } catch (err) {
      console.error('JWT Verification Failed:', err);
      return new Response('Invalid Token Signature', { status: 403 });
    }

    // 5. Set Secure Session Cookie
    const headers = new Headers();
    // HttpOnly, Secure, SameSite=Lax, Max-Age=1 hour (3600s)
    headers.append('Set-Cookie', `aim_session_token=${idToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`);
    headers.append('Location', '/integrity-portal'); // Redirect to dashboard
    
    return new Response(null, { status: 302, headers });

  } catch (error) {
    console.error('Callback Error:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
};   