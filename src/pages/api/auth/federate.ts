// src/pages/api/auth/federate.ts
export const prerender = false;
import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return new Response(null, { status: 302, headers: { Location: '/login?error=invalid_email' } });
    }

    const domain = email.split('@')[1].toLowerCase();

    // 🛡️ GITOPS LOGIC: Only allow domains you have explicitly enabled in Env Vars
    // Format: PRIVATE_TENANT_{DOMAIN_UPPERCASE}_CLIENT_ID
    const envVarPrefix = `PRIVATE_TENANT_${domain.replace(/[^a-z0-9]/g, '_').toUpperCase()}`;
    const clientId = import.meta.env[`${envVarPrefix}_CLIENT_ID`];
    const provider = import.meta.env[`${envVarPrefix}_PROVIDER`] || 'entra_id';
    
    // If no Env Var exists for this domain, reject the login (GitOps Gate)
    if (!clientId) {
      console.warn(`Blocked login attempt for unapproved domain: ${domain}`);
      return new Response(null, { 
        status: 302, 
        headers: { Location: '/login?error=unauthorized_domain' } 
      });
    }

    // Construct URLs dynamically based on provider
    let authUrl: string;
    if (provider === 'entra_id') {
      const tenantId = import.meta.env[`${envVarPrefix}_TENANT_ID`] || 'common';
      authUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`;
    } else {
      const oktaDomain = import.meta.env[`${envVarPrefix}_OKTA_DOMAIN`];
      authUrl = `https://${oktaDomain}/oauth2/default/v1/authorize`;
    }

    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      scope: 'openid email profile',
      redirect_uri: redirectUri,
      state: domain
    });

    return new Response(null, { status: 302, headers: { Location: `${authUrl}?${params.toString()}` } });

  } catch (error) {
    console.error('SSO Error:', error);
    return new Response(null, { status: 302, headers: { Location: '/login?error=handshake_failed' } });
  }
};   
