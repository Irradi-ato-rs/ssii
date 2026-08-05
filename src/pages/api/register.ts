// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute, APIContext } from 'astro';
import { getIdPConfig } from '../../config/tenants';

export const POST: APIRoute = async ({ request, locals }: APIContext) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString();

    if (!email || !email.includes('@')) {
      return new Response('Invalid email address', { status: 400 });
    }

    const domain = email.split('@')[1].toLowerCase();
    const config = getIdPConfig(email);

    // 1. Check if domain is pre-approved
    if (!config) {
      return new Response(JSON.stringify({ 
        error: 'Domain not authorized', 
        message: 'Your organization is not yet onboarded. Please contact support.' 
      }), { 
        status: 403, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // 2. FIX: Access secrets via locals.runtime.env (Cloudflare Workers standard)
    // globalThis.process.env does not exist in the Workers runtime
    const env = locals.runtime.env;
    const clientId = env[config.clientIdEnv];

    if (!clientId) {
      console.error(`MISSING SECRET: ${config.clientIdEnv}`);
      return new Response('Configuration error: Missing Client ID', { status: 500 });
    }

    // 3. Generate State Payload via Edge-Native Web Crypto APIs
    const statePayload = { domain, nonce: crypto.randomUUID() };
    const state = btoa(JSON.stringify(statePayload));

    // 4. Resolve the True Canonical Request Origin
    const host = request.headers.get('host') || new URL(request.url).host;
    const protocol = request.headers.get('x-forwarded-proto') || 'https';
    const origin = `${protocol}://${host}`;

    // 5. Construct IdP Authorization URL
    const authUrl = new URL(config.authorizationEndpoint);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', `${origin}/api/auth/callback`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email groups');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('login_hint', email);

    // 6. Set State Cookie & Redirect
    const headers = new Headers();
    headers.append('Set-Cookie', `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);
    headers.append('Location', authUrl.toString());

    return new Response(null, { status: 302, headers });

  } catch (error) {
    console.error('Registration Error:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
};   