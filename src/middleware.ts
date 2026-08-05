import { defineMiddleware } from 'astro:middleware';
import { jwtVerify, createRemoteJWKSet } from 'jose';

interface DynamicIdPConfig {
  issuer: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  tokenEndpoint: string;
  jwksUri: string;
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { request, locals, cookies } = context;
  const url = new URL(request.url);

  // 1. Structural Bypass: Skip evaluation for baseline routing zones to prevent loops
  if (url.pathname.startsWith('/api/auth') || url.pathname === '/' || url.pathname === '/login') {
    return next();
  }

  // 2. Extract Token Parameters Safely from standard Cookie strings
  const sessionToken = cookies.get('aim_session_token');

  if (!sessionToken || !sessionToken.value) {
    locals.user = null;
    return context.redirect('/?error=unauthenticated_session_gateway');
  }

  try {
    // Access environment variables natively via Astro request context parameters
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY as KVNamespace | undefined;

    if (!tenantDirectory) {
      console.error('[VoidMetric Middleware] Critical Reference VM_TENANT_DIRECTORY Binding Unreached');
      locals.user = null;
      return context.redirect('/?error=infrastructure_environment_fault');
    }

    // 3. Inspect the unverified token envelope to identify domain origins (Stateless Routing)
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed structural envelope signature matching criteria');
    
    const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
    const userEmailClaim = rawEnvelopePayload.email || rawEnvelopePayload.sub || '';
    const extractedDomain = userEmailClaim.split('@')[1];

    if (!extractedDomain) throw new Error('Identity claim missing explicit tenant domain context routing values');

    // 4. Resolve the explicit tenant profile dynamically out of Cloudflare's hidden storage vault
    const serializedConfig = await tenantDirectory.get(`domain:${extractedDomain}`);
    if (!serializedConfig) {
      console.error(`[VoidMetric Middleware] Domain routing configuration unrecognized: ${extractedDomain}`);
      locals.user = null;
      return context.redirect('/?error=tenant_access_denied');
    }
    const targetConfig = JSON.parse(serializedConfig) as DynamicIdPConfig;

    // Resolve the Client ID name mapping parameter inside your runtime ecosystem
    const resolvedAudienceId = runtimeEnv?.[targetConfig.clientIdEnv]?.trim();
    if (!resolvedAudienceId) {
      console.error(`[VoidMetric Middleware] Audience validation binding key unpopulated: ${targetConfig.clientIdEnv}`);
      locals.user = null;
      return context.redirect('/?error=configuration_runtime_fault');
    }

    // 5. Asymmetric JWKS cryptographic evaluation signature check against the tenant profile endpoints
    const JWKS = createRemoteJWKSet(new URL(targetConfig.jwksUri));
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: targetConfig.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s'
    });

    // 6. Map identity group claims directly to HTML authorization roles
    const directoryGroups = (payload.groups || payload.roles || []) as string[];
    let evaluatedRole: 'admin' | 'executive' | 'engineer' = 'engineer'; 

    if (directoryGroups.includes('VoidMetric_Admins') || directoryGroups.includes('Global_Admin')) {
      evaluatedRole = 'admin';
    } else if (directoryGroups.includes('VoidMetric_Executives') || directoryGroups.includes('C_Suite')) {
      evaluatedRole = 'executive';
    }

    // 7. Establish the active global user identity variables mapping context
    locals.user = {
      email: userEmailClaim,
      role: evaluatedRole,
      tenant: extractedDomain,
      rawClaimsPayload: payload
    };

    return next();

  } catch (err) {
    console.error('[VoidMetric Middleware Fault] JWT validation sequence aborted:', (err as Error).message);
    locals.user = null;
    
    // Expire the damaged session token cleanly
    cookies.delete('aim_session_token', { path: '/' });
    return context.redirect('/?error=session_invalidated_by_middleware');
  }
});
