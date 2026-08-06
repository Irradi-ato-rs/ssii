// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { getIdPConfig } from '../../config/tenants';

export const POST: APIRoute = async (context) => {
  const { request, locals } = context;
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

    // Fixed array parsing bug to prevent execution runtime crashes
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

    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env || {};
    const clientId = runtimeEnv[config.clientIdEnv];
    const clientSecret = runtimeEnv[config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      console.error(`MISSING SECRETS: ${config.clientIdEnv} or ${config.clientSecretEnv}`);
      return new Response(JSON.stringify({ error: 'Configuration error: Missing secrets' }), { 
        status: 500, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const statePayload = { domain, nonce: crypto.randomUUID() };
    const state = btoa(JSON.stringify(statePayload));

    const SITE_URL = runtimeEnv.SITE_URL || "https://fzoirm.com";
    const redirectUri = `${SITE_URL}/api/auth/callback`;

    const cleanAuthBase = String(config.authorizationEndpoint).trim();
    const federationQueryParameters = new URLSearchParams({
      client_id: String(clientId).trim(),
      scope: 'openid profile email User.Read Group.Read.All', 
      response_type: 'code',
      state: state,
      login_hint: email,
      redirect_uri: redirectUri
    });

    const finalOutboundHandshakeUrl = cleanAuthBase + (cleanAuthBase.includes('?') ? '&' : '?') + federationQueryParameters.toString();

    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append(
      'Set-Cookie', 
      `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`
    );

    return new Response(JSON.stringify({ success: true, redirectUrl: finalOutboundHandshakeUrl }), { 
      status: 200, 
      headers 
    });

  } catch (error) {
    console.error('=== REGISTER CRASH ===', error);
    return new Response(JSON.stringify({ error: 'Handshake failed', details: (error as Error).message }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' } 
    });
  }
};
