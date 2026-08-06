// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute, APIContext } from 'astro';
import { getIdPConfig } from '../../config/tenants';

// Astro 6: Import env directly from cloudflare:workers
import { env } from 'cloudflare:workers';

export const POST: APIRoute = async ({ request }: APIContext) => {
  console.log('=== REGISTER API HIT ===');
  
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString();

    console.log('Email received:', email);

    if (!email || !email.includes('@')) {
      console.error('Invalid email:', email);
      return new Response(JSON.stringify({ error: 'Invalid email address' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const domain = email.split('@')[1].toLowerCase();
    console.log('Extracted domain:', domain);

    const config = getIdPConfig(email);
    console.log('IdP Config found:', !!config);

    if (!config) {
      return new Response(JSON.stringify({ 
        error: 'Domain not authorized', 
        message: 'Your organization is not yet onboarded.' 
      }), { 
        status: 403, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // Astro 6: Access secrets via imported env
    const clientId = env[config.clientIdEnv];
    const clientSecret = env[config.clientSecretEnv];

    console.log('Client ID found:', !!clientId);
    console.log('Client Secret found:', !!clientSecret);

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

    // FIX: Use hardcoded SITE_URL from env (not request headers)
    const SITE_URL = env.SITE_URL || "https://ssii.fzoirm.com";
    const redirectUri = `${SITE_URL}/api/auth/callback`;
    
    console.log('Using Redirect URI:', redirectUri);

    // 5. Construct IdP Authorization URL
    const authUrl = new URL(config.authorizationEndpoint);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email groups');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('login_hint', email);

    // 6. Return JSON + Set-Cookie Header
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('Set-Cookie', `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);

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
    console.error('Stack:', (error as Error).stack);
    
    return new Response(JSON.stringify({ 
      error: 'Handshake failed', 
      details: (error as Error).message 
    }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' } 
    });
  }
};   