// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers'; // ✅ ASTRO 6 PATTERN
import { getIdPConfig } from '../../config/tenants';

export const POST: APIRoute = async ({ request, cookies }) => {
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

    const domain = email.split('@')[1].toLowerCase().trim();
    const config = getIdPConfig(email);

    if (!config) {
      return new Response(JSON.stringify({ 
        error: 'tenant_access_denied',
        message: 'Your organization is not yet onboarded.' 
      }), { 
        status: 403, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // ✅ ASTRO 6: Direct env access via cloudflare:workers
    const clientId = env[config.clientIdEnv]?.trim();
    const clientSecret = env[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error(`MISSING SECRETS: ${config.clientIdEnv} or ${config.clientSecretEnv}`);
      return new Response(JSON.stringify({ error: 'Configuration error: Missing secrets' }), { 
        status: 500, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    // ✅ Generate secure state + store in KV (not cookie)
    const state = crypto.randomUUID();
    const statePayload = { domain, email, nonce: state };
    
    // Store in KV with 5-minute expiration
    await env.SESSION.put(`oidc_state:${state}`, JSON.stringify(statePayload), { 
      expirationTtl: 300 
    });

    const rigidRedirectUri = "https://ssii.fzoirm.com/api/auth/callback";

    const cleanAuthBase = String(config.authorizationEndpoint).trim();
    const federationQueryParameters = new URLSearchParams({
      client_id: clientId,
      scope: 'openid profile email User.Read Group.Read.All',
      response_type: 'code',
      state: state, // ✅ Only send the UUID, not full payload
      login_hint: email,
      redirect_uri: rigidRedirectUri
    });

    const finalOutboundHandshakeUrl = cleanAuthBase + (cleanAuthBase.includes('?') ? '&' : '?') + federationQueryParameters.toString();

    console.log('=== REGISTER SUCCESS ===');
    console.log('Redirect URL:', finalOutboundHandshakeUrl);

    return new Response(JSON.stringify({ 
      success: true, 
      redirectUrl: finalOutboundHandshakeUrl 
    }), { 
      status: 200, 
      headers: { 'Content-Type': 'application/json' } 
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