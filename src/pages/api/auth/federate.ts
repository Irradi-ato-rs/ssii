export const prerender = false;
import type { APIRoute } from 'astro';

export const POST: APIRoute = async (context) => {
  const { request, cookies, locals } = context;
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return new Response(null, { status: 302, headers: { Location: '/login?error=invalid_email' } });
    }

    const domain = email.split('@')[1].toLowerCase();

    // Resolve Dynamic Vault Directory Bindings from Cloudflare's platform context
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Federation Gateway] Critical reference VM_TENANT_DIRECTORY unreached.');
      return new Response(null, { status: 302, headers: { Location: '/login?error=infrastructure_fault' } });
    }

    // Fetch the Hidden Tenant Routing Schema Configuration
    const tenantConfigRaw = await tenantDirectory.get(`domain:${domain}`);
    if (!tenantConfigRaw) {
      console.warn(`[VoidMetric Federation Gateway] Blocked unapproved domain node registration: ${domain}`);
      return new Response(null, { status: 302, headers: { Location: '/login?error=unauthorized_domain' } });
    }
    const tenantConfig = JSON.parse(tenantConfigRaw);

    // Extract the Client ID key name mapping from your hidden environment container variables
    const resolvedClientId = runtimeEnv?.[tenantConfig.clientIdEnv]?.trim();
    if (!resolvedClientId) {
      console.error(`[VoidMetric Federation Gateway] Audience key unpopulated in environment: ${tenantConfig.clientIdEnv}`);
      return new Response(null, { status: 302, headers: { Location: '/login?error=configuration_fault' } });
    }

    // Cryptographically Obscure State Tokens & Set CSRF Defenses
    const transactionStateToken = btoa(JSON.stringify({ domain, ts: Date.now() }));

    // Enforce Cross-Site Request Forgery validation parameters tracking cookie constraints
    cookies.set('oidc_state', transactionStateToken, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 300 // Valid for a 5-minute transaction window
    });

    // Construct Dynamic Target Authorization URLs
    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    const authUrl = new URL(tenantConfig.authorizationEndpoint || `${tenantConfig.issuer}/v1/authorize`);
    
    authUrl.searchParams.append('client_id', resolvedClientId);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'openid email profile');
    authUrl.searchParams.append('redirect_uri', redirectUri);
    authUrl.searchParams.append('state', transactionStateToken);

    return new Response(null, { status: 302, headers: { Location: authUrl.toString() } });

  } catch (error) {
    console.error('[VoidMetric Federation Gateway Exception] Handshake aborted:', error);
    return new Response(null, { status: 302, headers: { Location: '/login?error=handshake_failed' } });
  }
};
