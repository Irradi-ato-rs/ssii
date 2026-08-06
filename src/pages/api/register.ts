// src/pages/api/register.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// PRODUCTION-GRADE BOUNDARY GATEWAY ENGINE v5
export const POST: APIRoute = async ({ request, locals, cookies }) => {
  const executionStartTime = Date.now();
  const STANDARD_PROCESSING_LATENCY_MS = 120; // Constant latency anchor to block timing leaks

  try {
    const formData = await request.formData();
    const email = formData.get('email');

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      throw new Error('malformed_identity_vector');
    }

    const extractedDomain = email.split('@').pop()?.toLowerCase().trim() || '';
    
    // Hard structural boundary check against runtime namespace overrides
    if (!extractedDomain || extractedDomain.includes('.') === false) {
      throw new Error('invalid_identity_realm');
    }

    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Register Fault] Core KV binding missing');
      throw new Error('infrastructure_environment_fault');
    }

    // 1. Fetch Tenant Configuration Matrix
    const serializedConfig = await tenantDirectory.get(`domain:${extractedDomain}`);
    
    // Constant time alignment flag: Keep processing even if domain is unregistered
    const isRegisteredTenant = !!serializedConfig;
    const targetConfig = isRegisteredTenant 
      ? JSON.parse(serializedConfig) 
      : { issuer: '', clientIdEnv: '', jwksUri: '' };

    // Strict validation boundary for dynamic environment property lookup
    const targetKeyString = String(targetConfig.clientIdEnv).trim();
    const isKeySafe = /^[a-zA-Z0-9_]+$/.test(targetKeyString);
    
    const resolvedClientId = (isRegisteredTenant && isKeySafe) 
      ? runtimeEnv[targetKeyString]?.trim() 
      : null;

    if (!resolvedClientId) {
      throw new Error('tenant_access_denied');
    }

    // 2. CRYPTOGRAPHIC HANDSHAKE GENERATION (CSRF Safety Layer)
    // Create high-entropy cryptographically secure random bytes for the OAuth State
    const stateEntropyBuffer = new Uint8Array(32);
    crypto.getRandomValues(stateEntropyBuffer);
    const secureStateValue = Array.from(stateEntropyBuffer, byte => byte.toString(16).padStart(2, '0')).join('');

    // 3. SECURE COOKIE SETTINGS FOR THE AUTHENTICATION LIFECYCLE
    // Anchor the state cookie server-side using strict production isolation parameters
    cookies.set('__Host-oauth_state', secureStateValue, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 300 // Valid for 5 minutes maximum
    });

    // 4. CONSTRUCT THE OUTBOUND FEDERATION PATH
    // Build the clean target redirection address matching Microsoft Entra ID specifications
    const authorizationTarget = new URL(`${targetConfig.issuer}/oauth2/v2.0/authorize`);
    authorizationTarget.searchParams.set('client_id', resolvedClientId);
    authorizationTarget.searchParams.set('response_type', 'code');
    authorizationTarget.searchParams.set('redirect_uri', 'https://fzoirm.com');
    authorizationTarget.searchParams.set('response_mode', 'query');
    authorizationTarget.searchParams.set('scope', 'openid profile email');
    authorizationTarget.searchParams.set('state', secureStateValue);

    // 5. TIMING ATTACK MITIGATION ENFORCER
    // Pad execution duration to guarantee a constant response timeline
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
    // Constant time alignment padding container on failure paths as well
    const activeProcessingTime = Date.now() - executionStartTime;
    const remainingDelayPadding = STANDARD_PROCESSING_LATENCY_MS - activeProcessingTime;
    if (remainingDelayPadding > 0) {
      await new Promise(resolve => setTimeout(resolve, remainingDelayPadding));
    }

    const rawErrorMessage = err.message || 'handshake_negotiation_failed';
    const cleanErrorResponse = rawErrorMessage.replace(/[^a-zA-Z0-9_]/g, '');

    return new Response(JSON.stringify({ error: cleanErrorResponse }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
