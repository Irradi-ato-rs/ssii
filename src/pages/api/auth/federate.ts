// src/pages/api/auth/federate.ts

// CRITICAL: This line MUST be first. It tells Astro to deploy this as a Serverless Function.
// Without it, Cloudflare treats this as a static file, causing the 404 error.
export const prerender = false;

import type { APIRoute } from 'astro';

// Simple Tenant Registry
// In production, replace hardcoded IDs with import.meta.env.PRIVATE_... variables
const TENANTS: Record<string, { provider: string; authUrl: string; clientId: string }> = {
  // Add actual domains here for testing
  "iclassed.com": {
    provider: "entra_id",
    authUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    clientId: "YOUR_ENTRA_CLIENT_ID" 
  },
  "okta-tenant.com": {
    provider: "okta",
    authUrl: "https://dev-12345.okta.com/oauth2/default/v1/authorize",
    clientId: "YOUR_OKTA_CLIENT_ID" 
  }
};

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return new Response(null, { 
        status: 302, 
        headers: { Location: '/login?error=invalid_email' } 
      });
    }

    const domain = email.split('@')[1].toLowerCase();
    const tenant = TENANTS[domain];

    // If domain not found in registry, redirect to error
    if (!tenant) {
      return new Response(null, { 
        status: 302, 
        headers: { Location: '/login?error=unauthorized' } 
      });
    }

    // Construct the OAuth2 Redirect URL
    // Dynamically uses the current deployment URL (works for preview and production)
    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    
    const params = new URLSearchParams({
      client_id: tenant.clientId,
      response_type: 'code',
      scope: 'openid email profile groups',
      redirect_uri: redirectUri,
      state: domain // Pass domain to callback to identify tenant
    });

    const authUrl = `${tenant.authUrl}?${params.toString()}`;

    // Redirect user to Identity Provider (Entra ID or Okta)
    return new Response(null, { 
      status: 302, 
      headers: { Location: authUrl } 
    });

  } catch (error) {
    console.error('SSO Redirect Error:', error);
    return new Response(null, { 
      status: 302, 
      headers: { Location: '/login?error=handshake_failed' } 
    });
  }
};   
