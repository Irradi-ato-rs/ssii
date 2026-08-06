// src/pages/api/register.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// EXPLICIT FORCE COMPILE ID: HARD OVERWRITE REDIRECT GENERATION PIPELINE v9
export const POST: APIRoute = async ({ request, locals, cookies }) => {
  const executionStartTime = Date.now();
  const STANDARD_PROCESSING_LATENCY_MS = 120; // Constant latency tracking anchor to block timing loops

  try {
    const formData = await request.formData();
    const email = formData.get('email');

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      throw new Error('malformed_identity_vector');
    }

    const extractedDomain = email.split('@').pop()?.toLowerCase().trim() || '';
    
    if (!extractedDomain || extractedDomain.includes('.') === false) {
      throw new Error('invalid_identity_realm');
    }
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Register Fault] Core Cloudflare KV directory namespace binding missing');
      throw new Error('infrastructure_environment_fault');
    }

    // Fetch Target Tenant Configuration from private database storage instance
    const serializedConfig = await tenantDirectory.get(`domain:${extractedDomain}`);
    
    // Constant time alignment flag: Keep processing path uniform even if domain is unregistered
    const isRegisteredTenant = !!serializedConfig;
    const targetConfig = isRegisteredTenant 
      ? JSON.parse(serializedConfig) 
      : { issuer: '', clientIdEnv: '', jwksUri: '' };

    // Whitelist check against dynamic object property injection attacks
    const targetKeyString = String(targetConfig.clientIdEnv).trim();
    const isKeySafe = /^[a-zA-Z0-9_]+$/.test(targetKeyString);
    
    const resolvedClientId = (isRegisteredTenant && isKeySafe) 
      ? runtimeEnv[targetKeyString]?.trim() 
      : null;

    if (!resolvedClientId) {
      console.error(`[VoidMetric Register Warning] Unauthorized Domain or Missing Client ID for domain: ${extractedDomain}`);
      throw new Error('tenant_access_denied');
    }
    // Generate high-entropy secure state bytes to prevent CSRF exploits
    const stateEntropyBuffer = new Uint8Array(32);
    crypto.getRandomValues(stateEntropyBuffer);
    const secureStateValue = Array.from(stateEntropyBuffer, byte => byte.toString(16).padStart(2, '0')).join('');

    // Anchor the state cookie server-side via strict production criteria
    cookies.set('__Host-oauth_state', secureStateValue, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 300 // Valid for 5 minutes maximum
    });

    // Clean up issuer formatting string variations natively
    let cleanBaseIssuer = String(targetConfig.issuer).trim();
    if (cleanBaseIssuer.endsWith('/v2.0')) {
      cleanBaseIssuer = cleanBaseIssuer.replace('/v2.0', '');
    }
    if (cleanBaseIssuer.endsWith('/')) {
      cleanBaseIssuer = cleanBaseIssuer.slice(0, -1);
    }

    // Force absolute configuration construction block to override environmental drifts
    const authorizationTarget = new URL(`${cleanBaseIssuer}/oauth2/v2.0/authorize`);
    const rigidCallbackString = "https://ssii.fzoirm.com";

    authorizationTarget.searchParams.set('client_id', resolvedClientId);
    authorizationTarget.searchParams.set('response_type', 'code');
    authorizationTarget.searchParams.set('redirect_uri', rigidCallbackString);
    authorizationTarget.searchParams.set('response_mode', 'query');
    authorizationTarget.searchParams.set('scope', 'openid profile email');
    authorizationTarget.searchParams.set('state', secureStateValue);

    // Padding latency loop to neutralize cross-tenant timing evaluation checks
    const activeProcessingTime = Date.now() - executionStartTime;
    const remainingDelayPadding = STANDARD_PROCESSING_LATENCY_MS - activeProcessingTime;
    if (remainingDelayPadding > 0) {
      await new Promise(resolve => setTimeout(resolve, remainingDelayPadding));
    }

    return new Response(JSON.stringify({ redirectUrl: authorizationTarget.toString() }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err: any) {
    // Enforce constant execution duration even on edge failure states
    const activeProcessingTime = Date.now() - executionStartTime;
    const remainingDelayPadding = STANDARD_PROCESSING_LATENCY_MS - activeProcessingTime;
    if (remainingDelayPadding > 0) {
      await new Promise(resolve => setTimeout(resolve, remainingDelayPadding));
    }

    const rawErrorMessage = err.message || 'handshake_negotiation_failed';
    const cleanErrorResponse = rawErrorMessage.replace(/[^a-zA-Z0-9_]/g, '');

    // Return the technical error code back to your login.astro interface display box
    return new Response(JSON.stringify({ error: cleanErrorResponse }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
