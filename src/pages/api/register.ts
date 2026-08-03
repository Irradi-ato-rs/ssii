// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { getIdPConfig } from '../../config/tenants';
import { v4 as uuidv4 } from 'uuid';

export const POST: APIRoute = async ({ request, env }) => { // 1. Add 'env' to arguments
  const formData = await request.formData();
  const email = formData.get('email')?.toString();

  if (!email || !email.includes('@')) {
    return new Response('Invalid email address', { status: 400 });
  }

  const config = getIdPConfig(email);

  if (!config) {
    return new Response(JSON.stringify({ 
      error: 'Domain not authorized', 
      message: 'Your organization is not yet onboarded. Please contact support.' 
    }), { 
      status: 403, 
      headers: { 'Content-Type': 'application/json' } 
    });
  }

  const state = uuidv4();
  const url = new URL(request.url);
  const origin = url.origin;

  const authUrl = new URL(config.authorizationEndpoint);
  
  // 2. Resolve the actual Client ID from env using the key name
  const clientId = env[config.clientIdEnv]; 
  
  if (!clientId) {
    console.error(`Missing secret: ${config.clientIdEnv}`);
    return new Response('Configuration error', { status: 500 });
  }

  authUrl.searchParams.set('client_id', clientId); // 3. Use the resolved value
  authUrl.searchParams.set('redirect_uri', `${origin}/api/auth/callback`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email groups');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('login_hint', email);

  const headers = new Headers();
  headers.append('Set-Cookie', `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);
  headers.append('Location', authUrl.toString());

  return new Response(null, { status: 302, headers });
};   