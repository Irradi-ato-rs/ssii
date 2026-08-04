// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { getIdPConfig } from '../../config/tenants';
import { v4 as uuidv4 } from 'uuid';
import { env } from 'cloudflare:workers'; // CRITICAL: Import env from module

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString();

    if (!email || !email.includes('@')) {
      return new Response('Invalid email address', { status: 400 });
    }

    const config = getIdPConfig(email);

    // 1. Check if domain is pre-approved in tenants.ts
    if (!config) {
      return new Response(JSON.stringify({ 
        error: 'Domain not authorized', 
        message: 'Your organization is not yet onboarded. Please contact support.' 
      }), { 
        status: 403, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // 2. Resolve Secrets via Imported Env
    const clientId = env[config.clientIdEnv];
    const clientSecret = env[config.clientSecretEnv]; // Optional check, mostly needed in callback

    if (!clientId) {
      console.error(`MISSING SECRET: ${config.clientIdEnv}`);
      return new Response('Configuration error: Missing Client ID', { status: 500 });
    }

    // 3. Generate CSRF State
    const state = uuidv4();
    const url = new URL(request.url);
    const origin = url.origin;

    // 4. Construct IdP Authorization URL
    const authUrl = new URL(config.authorizationEndpoint);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', `${origin}/api/auth/callback`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email groups');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('login_hint', email);

    // 5. Set State Cookie & Redirect
    const headers = new Headers();
    headers.append('Set-Cookie', `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);
    headers.append('Location', authUrl.toString());

    return new Response(null, { status: 302, headers });

  } catch (error) {
    console.error('Registration Error:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
};   