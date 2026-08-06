// src/pages/api/auth/callback.ts
import type { APIRoute } from 'astro';

export const prerender = false;

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
}

export const GET: APIRoute = async (context) => {
  const { request, cookies, locals } = context;
  const url = new URL(request.url);
  
  const incomingCode = url.searchParams.get('code');
  const incomingState = url.searchParams.get('state');
  const oidcError = url.searchParams.get('error');

  // 1. Upstream Error Interception
  if (oidcError) {
    console.error(`[VoidMetric Callback] Upstream Provider Aborted: ${oidcError}`);
    return context.redirect(`/login?error=${oidcError}`);
  }

  // 2. HARD CSRF VERIFICATION ENGINE
  const anchorStateCookie = cookies.get('__Host-oauth_state');
  
  if (!anchorStateCookie || !anchorStateCookie.value || !incomingState || incomingState !== anchorStateCookie.value) {
    cookies.delete('__Host-oauth_state', { path: '/' });
    return context.redirect('/login?error=invalid_state');
  }

  cookies.delete('__Host-oauth_state', { path: '/' });

  if (!incomingCode) {
    return context.redirect('/login?error=malformed_auth_handshake');
  }

  try {
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      throw new Error('infrastructure_environment_fault');
    }

    // 3. ABSOLUTE IDENTITY REALM RESOLUTION
    const targetedDomainKey = "fzoirm.com";

    // Load Isolated Key-Vault Config Credentials
    const serializedConfig = await tenantDirectory.get(`domain:${targetedDomainKey}`);
    if (!serializedConfig) throw new Error('tenant_access_denied');
    
    const targetConfig = JSON.parse(serializedConfig) as DynamicIdPConfig;

    const targetClientKey = String(targetConfig.clientIdEnv).trim();
    const targetSecretKey = String(targetConfig.clientSecretEnv).trim();

    const resolvedClientId = /^[a-zA-Z0-9_]+$/.test(targetClientKey) ? runtimeEnv[targetClientKey] : null;
    const resolvedClientSecret = /^[a-zA-Z0-9_]+$/.test(targetSecretKey) ? runtimeEnv[targetSecretKey] : null;

    if (!resolvedClientId || !resolvedClientSecret) {
      throw new Error('configuration_runtime_fault');
    }

    // 4. Try the original tenant-specific endpoint path first to evaluate multitenant cross-trust
    const cleanTokenEndpoint = String(targetConfig.tokenEndpoint).trim();

    // 5. SERVER-TO-SERVER PROTOCOL EXCHANGE HANDSHAKE
    const tokenRequestPayload = new URLSearchParams({
      client_id: resolvedClientId.trim(),
      client_secret: resolvedClientSecret.trim(),
      grant_type: 'authorization_code',
      code: incomingCode,
      redirect_uri: 'https://fzoirm.com',
      scope: 'openid profile email'
    });

    const tokenResponse = await fetch(cleanTokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenRequestPayload.toString()
    });

    if (!tokenResponse.ok) {
      const rawFaultLog = await tokenResponse.text();
      console.error(`[VoidMetric Token Exchange Fault] Payload: ${rawFaultLog}`);
      
      // DIAGNOSTIC EXTRACTION LAYER: Parse out Microsoft's exact error token
      let rawErrorToken = 'session_negotiation_failed';
      try {
        const parsedFault = JSON.parse(rawFaultLog);
        if (parsedFault.error) {
          rawErrorToken = String(parsedFault.error_description || parsedFault.error);
        }
      } catch {
        rawErrorToken = rawFaultLog.substring(0, 50);
      }
      
      throw new Error(rawErrorToken);
    }

    const tokenData = await tokenResponse.json() as { id_token?: string; access_token?: string };
    const validatedIdentityToken = tokenData.id_token || tokenData.access_token;

    if (!validatedIdentityToken) {
      throw new Error('missing_cryptographic_claims');
    }

    // 6. ANCHOR PRODUCTION SESSION COOKIE
    cookies.set('aim_session_token', validatedIdentityToken, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 86400
    });

    return context.redirect('/integrity-portal');

  } catch (err: any) {
    console.error('[VoidMetric Callback Core Failure] Pipeline halted:', err.message);
    
    // Safely map and transmit the real error string down to the user login banner layout interface
    const cleanMappedError = err.message
      .replace(/[^a-zA-Z0-9_ ]/g, '')
      .replace(/\s+/g, '_')
      .toLowerCase();
    
    const uniqueCacheBusterStamp = Date.now();
    return context.redirect(`/login?error=${cleanMappedError}&v=${uniqueCacheBusterStamp}`);
  }
};
