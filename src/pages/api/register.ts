export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers'; // Direct Astro 6 edge runtime variable injection
import { getIdPConfig } from '../../config/tenants';

export const POST: APIRoute = async (context) => {
  const { request, cookies, redirect } = context;
  
  try {
    const formData = await request.formData();
    
    // 1. Strict Anti-CSRF Token Validation Gate
    const formAnchorToken = formData.get('form_anchor')?.toString();
    const cookieAnchorToken = cookies.get('__Host-login_form_anchor')?.value;

    if (!formAnchorToken || formAnchorToken !== cookieAnchorToken) {
      // Intentionally drop invalid cross-site requests back to login view node
      return redirect('/login?error=security_violation', 303);
    }
    // Burn the anchor token instantly upon check to prevent token reuse attempts
    cookies.delete('__Host-login_form_anchor', { path: '/' });

    const rawEmail = formData.get('email')?.toString().trim();

    // 2. Strict Input Structural Regex Validation
    if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)) {
      return redirect('/login?error=malformed_email', 303);
    }

    const email = rawEmail.toLowerCase();
    const domain = email.split('@').pop()?.trim() || '';

    // Extract tenant infrastructure mapping profile
    const config = getIdPConfig(email);
    if (!config) {
      return redirect('/login?error=tenant_access_denied', 303);
    }

    // 3. Safe Environment Mapping Integrity Check
    const clientIdEnvKey = config.clientIdEnv;
    const clientSecretEnvKey = config.clientSecretEnv;

    if (!clientIdEnvKey.startsWith('PRIVATE_ENTRA_') || !clientSecretEnvKey.startsWith('PRIVATE_ENTRA_')) {
      return redirect('/login?error=security_violation', 303);
    }

    const clientId = env[clientIdEnvKey]?.trim();
    const clientSecret = env[clientSecretEnvKey]?.trim();

    if (!clientId || !clientSecret) {
      return redirect('/login?error=config_error', 303);
    }

    // 4. Ephemeral State Token Generation
    const stateToken = crypto.randomUUID();
    const statePayload = { domain, email, nonce: stateToken };
    
    // Save transactional metadata inside Cloudflare KV for the callback phase
    await env.SESSION.put(`oidc_state:${stateToken}`, JSON.stringify(statePayload), { 
      expirationTtl: 300 // Bound to a tight 5-minute lifecycle window
    });

    // 5. Secure Host-Locked Cookie Allocation
    cookies.set('__Host-auth_state_verification', stateToken, {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax', // Mandatory to handle cross-site OIDC callback state validation passes
      maxAge: 300
    });

    // 6. Complete and Rigid Parameter Handshake Buildout
    const finalOutboundHandshakeUrl = new URL(String(config.authorizationEndpoint).trim());
    finalOutboundHandshakeUrl.searchParams.set('client_id', clientId);
    finalOutboundHandshakeUrl.searchParams.set('scope', 'openid profile email User.Read Group.Read.All');
    finalOutboundHandshakeUrl.searchParams.set('response_type', 'code');
    finalOutboundHandshakeUrl.searchParams.set('state', stateToken);
    finalOutboundHandshakeUrl.searchParams.set('login_hint', email);
    finalOutboundHandshakeUrl.searchParams.set('redirect_uri', "https://fzoirm.com");

    // 7. Authoritative Server-Driven 303 See Other Redirect Handover
    return redirect(finalOutboundHandshakeUrl.toString(), 303);

  } catch (error) {
    // Fail-safe protection fallback to shield the core website structure from crashes
    return redirect('/login?error=internal_gateway_fault', 303);
  }
};
