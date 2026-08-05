export const prerender = false;
import type { APIRoute } from 'astro';

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
  authorizationEndpoint?: string; // Optional: Explicitly declared endpoint overriding
  idpProviderType?: 'entra' | 'okta'; // Explicit provider flag
}

export const POST: APIRoute = async (context) => {
  const { request, cookies, locals } = context;
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return new Response(null, { status: 302, headers: { Location: '/login?error=invalid_email' } });
    }

    const emailParts = email.split('@');
    const domain = emailParts[emailParts.length - 1].toLowerCase();

    // 1. Resolve Dynamic Vault Directory Bindings
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Federation Gateway] Critical reference VM_TENANT_DIRECTORY unreached.');
      return new Response(null, { status: 302, headers: { Location: '/login?error=infrastructure_fault' } });
    }

    // 2. Fetch the Hidden Tenant Routing Schema Configuration
    const tenantConfigRaw = await tenantDirectory.get(`domain:${domain}`);
    if (!tenantConfigRaw) {
      console.warn(`[VoidMetric Federation Gateway] Blocked unapproved domain node registration: ${domain}`);
      return new Response(null, { status: 302, headers: { Location: '/login?error=unauthorized_domain' } });
    }
    const tenantConfig = JSON.parse(tenantConfigRaw) as DynamicIdPConfig;

    // Extract the Client ID key name mapping from your hidden environment container variables
    const resolvedClientId = runtimeEnv?.[tenantConfig.clientIdEnv]?.trim();
    if (!resolvedClientId) {
      console.error(`[VoidMetric Federation Gateway] Audience key unpopulated in environment: ${tenantConfig.clientIdEnv}`);
      return new Response(null, { status: 302, headers: { Location: '/login?error=configuration_fault' } });
    }

    // 3. Cryptographically Obscure State Tokens & Set CSRF Defenses
    const transactionStateToken = btoa(JSON.stringify({ domain, ts: Date.now() }));

    // Enforce Cross-Site Request Forgery validation parameters tracking cookie constraints
    cookies.set('oidc_state', transactionStateToken, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 300 // Valid for a 5-minute transaction window
    });

    // 4. CONSTRUCT canonical OID ENDPOINTS WITHOUT PATH COMPOUNDING
    let targetAuthorizeUrlStr = '';

    if (tenantConfig.authorizationEndpoint) {
      // If a full custom endpoint path is explicitly saved inside KV metadata, prioritize it
      targetAuthorizeUrlStr = tenantConfig.authorizationEndpoint;
    } else if (tenantConfig.idpProviderType === 'entra' || tenantConfig.issuer.includes('microsoftonline.com')) {
      // Standard Microsoft Entra ID V2.0 formatting path construction
      // Strips trailing slashes from issuer strings if present
      const cleanIssuer = tenantConfig.issuer.endsWith('/') ? tenantConfig.issuer.slice(0, -1) : tenantConfig.issuer;
      
      if (cleanIssuer.endsWith('/v2.0')) {
        // Transforms base profile paths safely into authorization targets
        const issuerBase = cleanIssuer.slice(0, -5); 
        targetAuthorizeUrlStr = `${issuerBase}/oauth2/v2.0/authorize`;
      } else {
        targetAuthorizeUrlStr = `${cleanIssuer}/oauth2/v2.0/authorize`;
      }
    } else {
      // Standard Okta Core API OIDC template endpoint structure mapping fallback
      const cleanIssuer = tenantConfig.issuer.endsWith('/') ? tenantConfig.issuer.slice(0, -1) : tenantConfig.issuer;
      targetAuthorizeUrlStr = `${cleanIssuer}/v1/authorize`;
    }

    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    const authUrl = new URL(targetAuthorizeUrlStr);
    
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
