// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute, APIContext } from 'astro';
import { getIdPConfig } from '../../config/tenants';
import { env } from 'cloudflare:workers';

export const POST: APIRoute = async ({ request }: APIContext) => {
  console.log('=== REGISTER API HIT ===');
  
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString();

    if (!email || !email.includes('@')) {
      return new Response(JSON.stringify({ error: 'Invalid email address' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const domain = email.split('@')[1].toLowerCase();
    const config = getIdPConfig(email);

    if (!config) {
      return new Response(JSON.stringify({ 
        error: 'Domain not authorized', 
        message: 'Your organization is not yet onboarded.' 
      }), { 
        status: 403, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const clientId = env[config.clientIdEnv];
    const clientSecret = env[config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      console.error(`MISSING SECRETS: ${config.clientIdEnv} or ${config.clientSecretEnv}`);
      return new Response(JSON.stringify({ error: 'Configuration error: Missing secrets' }), { 
        status: 500, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // 3. Generate State Payload
    const statePayload = { domain, nonce: crypto.randomUUID() };
    const state = btoa(JSON.stringify(statePayload));

    // 4. Resolve Canonical Origin
    const SITE_URL = env.SITE_URL || "https://ssii.fzoirm.com";
    const redirectUri = `${SITE_URL}/api/auth/callback`;

    // 5. Construct IdP Authorization URL
    const authUrl = new URL(config.authorizationEndpoint);
    authUrl.searchParams.set('client_id', clientId);
    // FIX: Removed 'groups', added 'User.Read Group.Read.All'
    authUrl.searchParams.set('scope', 'openid profile email User.Read Group.Read.All');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('login_hint', email);
    authUrl.searchParams.set('redirect_uri', redirectUri);

    // 6. Return JSON + Set-Cookie Header
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    
    // FIX: Explicit Path=/ to ensure cookie is sent back on callback
    headers.append(
      'Set-Cookie', 
      `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`
    );

    console.log('=== REGISTER SUCCESS ===');
    console.log('Redirect URL:', authUrl.toString());

    return new Response(JSON.stringify({ 
      success: true, 
      redirectUrl: authUrl.toString() 
    }), { 
      status: 200, 
      headers 
    });

  } catch (error) {
    console.error('=== REGISTER CRASH ===');
    console.error('Error:', error);
    
    return new Response(JSON.stringify({ 
      error: 'Handshake failed', 
      details: (error as Error).message 
    }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' } 
    });
  }
};   