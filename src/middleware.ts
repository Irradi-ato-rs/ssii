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

  // 1. ROBUST TRAILING-SLASH NORMALIZATION
  // Strips trailing slashes seamlessly to prevent Cloudflare Pages routing bypass bugs
  let cleanPath = url.pathname;
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  // 2. EXPLICIT PUBLIC ROUTE ALLOW-LIST
  // Whitelists all informational nodes required before an active session is established
  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];

  if (url.pathname.startsWith('/api/auth') || publicRoutes.includes(cleanPath)) {
    return next();
  }

  // 3. Extract Session Parameters safely via Astro Cookie API
  const sessionToken = cookies.get('aim_session_token');

  if (!sessionToken || !sessionToken.value) {
    locals.user = null;
    return context.redirect('/?error=unauthenticated_session_gateway');
  }

  try {
    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY as KVNamespace | undefined;

    if (!tenantDirectory) {
      console.error('[VoidMetric Middleware] Critical Reference VM_TENANT_DIRECTORY Binding Unreached');
      locals.user = null;
      return context.redirect('/?error=infrastructure_environment_fault');
    }

    // 4. Inspect the unverified token envelope to isolate domain roots (Stateless Routing)
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed structural envelope signature matching criteria');
    
    // Target the second chunk index [1] to safely extract the payload section
    const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
    const userEmailClaim = rawEnvelopePayload.email || rawEnvelopePayload.sub || '';
    const domainArray = userEmailClaim.split('@');
    const extractedDomain = domainArray[domainArray.length - 1]?.toLowerCase();

    if (!extractedDomain) throw new Error('Identity claim missing explicit tenant domain context routing values');

    // 5. Fetch the explicit tenant profile dynamically out of Cloudflare's hidden storage vault
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

    // 6. Asymmetric JWKS cryptographic signature check against the tenant profile endpoints
    const JWKS = createRemoteJWKSet(new URL(targetConfig.jwksUri));
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: targetConfig.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s'
    });

    // 7. Map directory group claims directly to security access roles
    const directoryGroups = (payload.groups || payload.roles || []) as string[];
    let evaluatedRole: 'admin' | 'executive' | 'engineer' = 'engineer'; 

    if (directoryGroups.includes('VoidMetric_Admins') || directoryGroups.includes('Global_Admin')) {
      evaluatedRole = 'admin';
    } else if (directoryGroups.includes('VoidMetric_Executives') || directoryGroups.includes('C_Suite')) {
      evaluatedRole = 'executive';
    }

    // Establish the active global user identity variables mapping context
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
