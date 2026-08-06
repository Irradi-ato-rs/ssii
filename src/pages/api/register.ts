// src/pages/api/register.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// ENFORCED GLOBAL PROTOCOL ENTRANCE MATRIX v10
export const POST: APIRoute = async ({ request, locals, cookies }) => {
  const executionStartTime = Date.now();
  const STANDARD_PROCESSING_LATENCY_MS = 120;

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
      console.error('[VoidMetric Register Fault] Core KV binding namespace configuration missing');
      throw new Error('infrastructure_environment_fault');
    }

    // Retrieve target client configuration map from private storage vault
    const serializedConfig = await tenantDirectory.get(`domain:${extractedDomain}`);
    
    const isRegisteredTenant = !!serializedConfig;
    const targetConfig = isRegisteredTenant 
      ? JSON.parse(serializedConfig) 
      : { issuer: '', clientIdEnv: '', jwksUri: '' };

    // Prevent dynamic property lock evaluation bypasses
    const targetKeyString = String(targetConfig.clientIdEnv).trim();
    const isKeySafe = /^[a-zA-Z0-9_]+$/.test(targetKeyString);
    
    const resolvedClientId = (isRegisteredTenant && isKeySafe) 
      ? runtimeEnv[targetKeyString]?.trim() 
      : null;

    if (!resolvedClientId) {
      console.error(`[VoidMetric Register Failure] Unauthorized Domain or Missing Client ID for domain: ${extractedDomain}`);
      throw new Error('tenant_access_denied');
    }
    // Generate high-entropy state payload vectors to defend against CSRF exploits
    const stateEntropyBuffer = new Uint8Array(32);
    crypto.getRandomValues(stateEntropyBuffer);
    const secureStateValue = Array.from(stateEntropyBuffer, byte => byte.toString(16).padStart(2, '0')).join('');

    // Anchor verification context using server-side __Host cookie isolation parameters
    cookies.set('__Host-oauth_state', secureStateValue, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 300
    });

    // Normalize issuer strings to guarantee trailing path consistency
    let cleanBaseIssuer = String(targetConfig.issuer).trim();
    if (cleanBaseIssuer.endsWith('/v2.0')) {
      cleanBaseIssuer = cleanBaseIssuer.replace('/v2.0', '');
    }
    if (cleanBaseIssuer.endsWith('/')) {
      cleanBaseIssuer = cleanBaseIssuer.slice(0, -1);
    }

    // RIGID GLOBAL ENFORCEMENT: Absolute URL string constructions
    const absoluteTargetEndpoint = `${cleanBaseIssuer}/oauth2/v2.0/authorize`;
    const authorizationTarget = new URL(absoluteTargetEndpoint);
    const rigidCallbackString = "https://fzoirm.com";

    authorizationTarget.searchParams.set('client_id', resolvedClientId);
    authorizationTarget.searchParams.set('response_type', 'code');
    authorizationTarget.searchParams.set('redirect_uri', rigidCallbackString);
    authorizationTarget.searchParams.set('response_mode', 'query');
    authorizationTarget.searchParams.set('scope', 'openid profile email');
    authorizationTarget.searchParams.set('state', secureStateValue);

    // Timing attack mitigation latency engine padding block
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
