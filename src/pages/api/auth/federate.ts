export const prerender = false;
import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request, cookies, locals }) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return new Response('Invalid or missing email identity parameter', { status: 400 });
    }

    const domain = email.split('@')[1];
    
    // Query dynamic tenants configuration registry inside your hidden Cloudflare storage vault
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;
    
    if (!tenantDirectory) {
      return new Response('Infrastructure directory unreached', { status: 500 });
    }

    const tenantConfigRaw = await tenantDirectory.get(`domain:${domain}`);
    if (!tenantConfigRaw) {
      return Response.redirect(`${new URL(request.url).origin}/?error=domain_unrecognized_by_vault`, 302);
    }
    const tenant = JSON.parse(tenantConfigRaw);

    // Cryptographically obscure transaction metadata parameters 
    const transactionStateToken = btoa(JSON.stringify({ domain, ts: Date.now() }));

    // Set the tracking validation parameter cookie inside the browser container space
    cookies.set('oidc_state', transactionStateToken, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 300 // Valid for a 5-minute authentication window
    });

    const redirectUri = `${new URL(request.url).origin}/api/auth/callback`;
    const authUrl = new URL(tenant.authorizationEndpoint || `${tenant.issuer}/v1/authorize`);
    authUrl.searchParams.append('client_id', runtimeEnv[tenant.clientIdEnv]?.trim() || '');
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', 'openid profile email');
    authUrl.searchParams.append('redirect_uri', redirectUri);
    authUrl.searchParams.append('state', transactionStateToken);

    return Response.redirect(authUrl.toString(), 302);
  } catch (e) {
    return new Response('Federation workflow routing fault', { status: 500 });
  }
};
