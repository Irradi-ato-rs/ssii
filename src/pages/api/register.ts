// src/pages/api/register.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { getIdPConfig } from '../../config/tenants';

export const POST: APIRoute = async ({ request, cookies }) => {
  try {
    const formData = await request.formData();
    const rawEmail = formData.get('email')?.toString().trim();

    // 1. Strict Structural Email Validation Regex
    if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)) {
      return new Response(JSON.stringify({ error: 'Malformed email target structural footprint.' }), { 
        status: 400, 
        headers: { 'Content-Type': 'application/json' } 
      });
    }

    const email = rawEmail.toLowerCase();
    const domain = email.split('@').pop()?.trim();

    const config = getIdPConfig(email);
    if (!config) {
      return new Response(JSON.stringify({ error: 'tenant_access_denied' }), { status: 403 });
    }

    // 2. Safe Environment Scope Guardrails
    const clientIdEnvKey = config.clientIdEnv;
    const clientSecretEnvKey = config.clientSecretEnv;

    if (!clientIdEnvKey.startsWith('OIDC_') || !clientSecretEnvKey.startsWith('OIDC_')) {
      return new Response(JSON.stringify({ error: 'System violation: Prohibited configuration space access.' }), { status: 400 });
    }

    const clientId = env[clientIdEnvKey]?.trim();
    const clientSecret = env[clientSecretEnvKey]?.trim();

    if (!clientId || !clientSecret) {
      return new Response(JSON.stringify({ error: 'Missing federation runtime credential maps.' }), { status: 500 });
    }

    // 3. Cryptographic State Verification Anchor
    const stateToken = crypto.randomUUID();
    const statePayload = { domain, email, nonce: stateToken };
    
    // Store in KV (For callback validation data payload extraction)
    await env.SESSION.put(`oidc_state:${stateToken}`, JSON.stringify(statePayload), { 
      expirationTtl: 300 
    });

    // 4. Set __Host- Cookie (NO domain attribute allowed per RFC 6265)
    cookies.set('__Host-auth_state_verification', stateToken, {
      path: '/',        // Required for __Host- prefix
      secure: true,     // Required for __Host- prefix
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 300
    });

    // 5. Rigid Formatted Endpoint Buildout
    const finalOutboundHandshakeUrl = new URL(String(config.authorizationEndpoint).trim());
    finalOutboundHandshakeUrl.searchParams.set('client_id', clientId);
    finalOutboundHandshakeUrl.searchParams.set('scope', 'openid profile email User.Read Group.Read.All');
    finalOutboundHandshakeUrl.searchParams.set('response_type', 'code');
    finalOutboundHandshakeUrl.searchParams.set('state', stateToken);
    finalOutboundHandshakeUrl.searchParams.set('login_hint', email);
    finalOutboundHandshakeUrl.searchParams.set('redirect_uri', "https://ssii.fzoirm.com/api/auth/callback");

    // 6. Force Authoritative Status Code 303 Redirect for Server-Driven Navigation
    return new Response(null, { 
      status: 303, 
      headers: { 'Location': finalOutboundHandshakeUrl.toString() } 
    });

  } catch (error) {
    console.error('[VoidMetric Auth] Register Crash:', error);
    return new Response(JSON.stringify({ error: 'System fault context execution exception.' }), { status: 500 });
  }
};   