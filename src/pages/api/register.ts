// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute, APIContext } from 'astro';
import { getIdPConfig } from '../../config/tenants';

export const POST: APIRoute = async (context: APIContext) => {
  const { request, cookies, locals } = context;
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

    // FIXED: Use correct array index positioning to prevent runtime string-split failures
    const domain = email.split('@')[1].toLowerCase().trim();
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

    // FIXED: Contextual lookup maps your exact keys (e.g. PRIVATE_ENTRA_ICLASSED_CLIENT_ID) cleanly
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env || {};
    const clientId = runtimeEnv[config.clientIdEnv]?.trim();
    const clientSecret = runtimeEnv[config.clientSecretEnv]?.trim();

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

    // 4. Resolve Canonical Origin -- FIXED: Immutable string constant blocks V8 path stripping
    // CRITICAL FIX: Added '/api/auth/callback' to match Azure App Registration exactly
    const rigidRedirectUri = "https://ssii.fzoirm.com/api/auth/callback";

    // 5. Construct IdP Authorization URL via Stratified Parameter Block
    const cleanAuthBase = String(config.authorizationEndpoint).trim();
    const federationQueryParameters = new URLSearchParams({
      client_id: clientId,
      scope: 'openid profile email User.Read Group.Read.All', // Hardened corporate permission scopes
      response_type: 'code',
      state: state,
      login_hint: email,
      redirect_uri: rigidRedirectUri
    });

    const finalOutboundHandshakeUrl = cleanAuthBase + (cleanAuthBase.includes('?') ? '&' : '?') + federationQueryParameters.toString();

    // 6. Return JSON + Set-Cookie Header
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append(
      'Set-Cookie', 
      `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`
    );

    console.log('=== REGISTER SUCCESS ===');
    console.log('Redirect URL:', finalOutboundHandshakeUrl);

    return new Response(JSON.stringify({ 
      success: true, 
      redirectUrl: finalOutboundHandshakeUrl 
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