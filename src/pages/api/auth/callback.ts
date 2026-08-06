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

  // 1. Upstream Provider Failure Interception
  if (oidcError) {
    console.error(`[VoidMetric Callback] Upstream Provider Aborted: ${oidcError}`);
    return context.redirect(`/login?error=${oidcError}`);
  }

  // 2. HARD CSRF VERIFICATION BOUNDARY ASSERTION
  const anchorStateCookie = cookies.get('__Host-oauth_state');
  
  if (!anchorStateCookie || !anchorStateCookie.value || !incomingState || incomingState !== anchorStateCookie.value) {
    cookies.delete('__Host-oauth_state', { path: '/' });
    return context.redirect('/login?error=invalid_state');
  }

  // Force instant state cookie eviction to completely destroy reuse vectors
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

    // 3. TARGET REALM DETERMINATION
    // Force direct configuration resolution matching your active directory domain key
    const targetedDomainKey = "fzoirm.com";

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
    // 4. SECURE PROTOCOL TRANSACTION ENFORCEMENT
    // Establish literal parameter strings to bypass variable environmental data drifts
    const cleanTokenEndpoint = String(targetConfig.tokenEndpoint).trim();
    const rigidCallbackString = "https://fzoirm.com";

    const tokenRequestPayload = new URLSearchParams({
      client_id: resolvedClientId.trim(),
      client_secret: resolvedClientSecret.trim(),
      grant_type: 'authorization_code',
      code: incomingCode,
      redirect_uri: rigidCallbackString,
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
    // 5. ANCHOR PRODUCTION SESSION COOKIE Context Entry
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
    
    const cleanMappedError = err.message
      .replace(/[^a-zA-Z0-9_ ]/g, '')
      .replace(/\s+/g, '_')
      .toLowerCase();
    
    const uniqueCacheBusterStamp = Date.now();
    return context.redirect(`/login?error=${cleanMappedError}&v=${uniqueCacheBusterStamp}`);
  }
};
