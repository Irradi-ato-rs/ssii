// src/pages/api/auth/federate.ts
export const prerender = false; // CRITICAL: Must be first

import type { APIRoute } from 'astro';

// src/pages/api/auth/federate.ts
import type { APIRoute } from 'astro';

// Simple Tenant Registry (Expand this as needed)
const TENANTS: Record<string, { provider: string; authUrl: string; clientId: string }> = {
  "example.com": {
    provider: "entra_id",
    authUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    clientId: "YOUR_ENTRA_CLIENT_ID" // Replace later with Env Var
  },
  "okta-tenant.com": {
    provider: "okta",
    authUrl: "https://dev-12345.okta.com/oauth2/default/v1/authorize",
    clientId: "YOUR_OKTA_CLIENT_ID" // Replace later with Env Var
  }
};

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return new Response(null, { status: 302, headers: { Location: '/login?error=invalid_email' } });
    }

    const domain = email.split('@')[1].toLowerCase();
    const tenant = TENANTS[domain];

    // If domain not found, redirect to error
    if (!tenant) {
      return new Response(null, { status: 302, headers: { Location: '/login?error=unauthorized' } });
    }

    // Construct the OAuth2 Redirect URL
    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    const params = new URLSearchParams({
      client_id: tenant.clientId,
      response_type: 'code',
      scope: 'openid email profile groups',
      redirect_uri: redirectUri,
      state: domain // Pass domain to callback to identify tenant
    });

    const authUrl = `${tenant.authUrl}?${params.toString()}`;

    return new Response(null, { status: 302, headers: { Location: authUrl } });

  } catch (error) {
    console.error('SSO Redirect Error:', error);
    return new Response(null, { status: 302, headers: { Location: '/login?error=handshake_failed' } });
  }
};   
