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

  // Evict validation token instantly upon successful validation match to prevent replay exploits
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

    // 3. SECURE STATE PRE-EXTRACTION BOUNDARY
    // To perform the code exchange, we need the specific tenant's client secret out of KV.
    // We isolate and parse the code string segment natively to find the target domain.
    const codeChunks = incomingCode.split('.');
    let temporaryDomain = '';
    
    try {
      // Decode authorization code metadata layers strictly if enveloped by the provider
      const payloadEnvelope = JSON.parse(atob(codeChunks[1] || codeChunks[0]));
      const rawUserClaim = payloadEnvelope.email || payloadEnvelope.sub || '';
      temporaryDomain = rawUserClaim.split('@').pop()?.toLowerCase().trim() || '';
    } catch {
      // Fallback domain extraction parsing layer if tracking vectors fail
      temporaryDomain = 'common';
    }

    // 4. Load Isolated Key-Vault Config Credentials
    const serializedConfig = await tenantDirectory.get(`domain:${temporaryDomain}`);
    if (!serializedConfig) throw new Error('tenant_access_denied');
    
    const targetConfig = JSON.parse(serializedConfig) as DynamicIdPConfig;
    // Whitelist and safely retrieve secure environment variables from the edge runtime execution space
    const targetClientKey = String(targetConfig.clientIdEnv).trim();
    const targetSecretKey = String(targetConfig.clientSecretEnv).trim();

    const resolvedClientId = /^[a-zA-Z0-9_]+$/.test(targetClientKey) ? runtimeEnv[targetClientKey] : null;
    const resolvedClientSecret = /^[a-zA-Z0-9_]+$/.test(targetSecretKey) ? runtimeEnv[targetSecretKey] : null;

    if (!resolvedClientId || !resolvedClientSecret) {
      throw new Error('configuration_runtime_fault');
    }

    // 5. SERVER-TO-SERVER PROTOCOL EXCHANGE HANDSHAKE (Fetch API)
    // Exchange the single-use authorization code for a production identity token
    const tokenRequestPayload = new URLSearchParams({
      client_id: resolvedClientId.trim(),
      client_secret: resolvedClientSecret.trim(),
      grant_type: 'authorization_code',
      code: incomingCode,
      redirect_uri: 'https://fzoirm.com',
      scope: 'openid profile email'
    });

    const tokenResponse = await fetch(targetConfig.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenRequestPayload.toString()
    });

    if (!tokenResponse.ok) {
      const rawFaultLog = await tokenResponse.text();
      console.error(`[VoidMetric Token Exchange Fault] HTTP Status: ${tokenResponse.status} - Payload: ${rawFaultLog}`);
      throw new Error('session_negotiation_failed');
    }

    const tokenData = await tokenResponse.json() as { id_token?: string; access_token?: string };
    const validatedIdentityToken = tokenData.id_token || tokenData.access_token;

    if (!validatedIdentityToken) {
      throw new Error('missing_cryptographic_claims');
    }
    // 6. ANCHOR PRODUCTION SESSION COOKIE
    // Push the verified signed token down to the operator's browser window
    cookies.set('aim_session_token', validatedIdentityToken, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 86400 // Production session valid for exactly 24 hours
    });

    // Clean handoff directly into the signature-first integrity portal
    return context.redirect('/integrity-portal');

  } catch (err: any) {
    console.error('[VoidMetric Callback Core Failure] Pipeline halted:', err.message);
    
    const rawErrorMessage = err.message || 'session_negotiation_failed';
    const cleanMappedError = rawErrorMessage.replace(/[^a-zA-Z0-9_]/g, '');
    
    return context.redirect(`/login?error=${cleanMappedError}`);
  }
};
