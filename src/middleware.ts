// src/middleware.ts
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

  // 1. Normalize Path
  let cleanPath = url.pathname;
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  // 2. Hard Asset Exclusion Matrix
  const isStaticAsset = 
    url.pathname.startsWith('/_astro') || 
    url.pathname === '/favicon.ico' ||
    url.pathname.includes('.') || 
    url.pathname.startsWith('/@vite') ||
    url.pathname.startsWith('/src/');

  if (isStaticAsset) {
    return next();
  }

  // Public Document Routes & API Handlers
  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];
  const isApiRoute = 
    url.pathname === '/api/register' || 
    url.pathname === '/api/auth/callback' || 
    url.pathname.startsWith('/api/auth/');   
  
  if (isApiRoute || publicRoutes.includes(cleanPath)) {
    return next();
  }

  // 3. Extract Session Token
  const sessionToken = cookies.get('aim_session_token');
  if (!sessionToken || !sessionToken.value) {
    locals.user = null;
    return new Response(null, { 
      status: 302, 
      headers: { 'Location': '/login?error=unauthenticated_session_gateway' } 
    });
  }

  try {
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Middleware] KV Binding Missing');
      locals.user = null;
      return new Response(null, { 
        status: 302, 
        headers: {
          'Set-Cookie': 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
          'Location': '/login?error=infrastructure_environment_fault'
        } 
      });
    }

    // 4. CRYPTOGRAPHIC ISOLATION BOUNDARY
    // Read the unverified payload strictly to find the directory mapping domain
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed token envelope structure');
    
    // Safely parse inside a try/catch container to block malicious payload crashes
    let temporaryDomain = '';
    try {
      const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
      const userEmailClaim = rawEnvelopePayload.email || rawEnvelopePayload.sub || '';
      temporaryDomain = userEmailClaim.split('@').pop()?.toLowerCase() || '';
    } catch {
      throw new Error('Invalid token payload serialization');
    }

    if (!temporaryDomain) throw new Error('Missing identity provider origin claim');

    // 5. Fetch Key Vault Signature Configuration
    const serializedConfig = await tenantDirectory.get(`domain:${temporaryDomain}`);
    if (!serializedConfig) {
      console.error(`[VoidMetric Middleware] Unregistered Domain Attempt: ${temporaryDomain}`);
      locals.user = null;
      return new Response(null, { 
        status: 302, 
        headers: {
          'Set-Cookie': 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
          'Location': '/login?error=tenant_access_denied'
        } 
      });
    }
    const targetConfig = JSON.parse(serializedConfig) as DynamicIdPConfig;

    const resolvedAudienceId = runtimeEnv?.[targetConfig.clientIdEnv]?.trim();
    if (!resolvedAudienceId) {
      locals.user = null;
      return new Response(null, { 
        status: 302, 
        headers: {
          'Set-Cookie': 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
          'Location': '/login?error=configuration_runtime_fault'
        } 
      });
    }

    // 6. CRYPTOGRAPHIC ENFORCEMENT LAYER (Signature-First Authorization)
    // The token is unvalidated until this step passes successfully
    const JWKS = createRemoteJWKSet(new URL(targetConfig.jwksUri));
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: targetConfig.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s'
    });

    // 7. IN-FLIGHT EXPIRATION HARD ASSERTION
    // Prevent stale, replayed, or expired token hijackings at the edge
    const currentUnixTimestamp = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < currentUnixTimestamp) {
      throw new Error('Token payload lifetime validity period expired');
    }

    // 8. Secure Trusted Role Mapping
    const validatedEmail = (payload.email || payload.sub || '') as string;
    const directoryGroups = (payload.groups || payload.roles || []) as string[];
    let evaluatedRole: 'admin' | 'executive' | 'engineer' = 'engineer'; 

    if (directoryGroups.includes('VoidMetric_Admins') || directoryGroups.includes('Global_Admin')) {
      evaluatedRole = 'admin';
    } else if (directoryGroups.includes('VoidMetric_Executives') || directoryGroups.includes('C_Suite')) {
      evaluatedRole = 'executive';
    }

    // Populate secure runtime context data cleanly
    locals.user = {
      email: validatedEmail,
      role: evaluatedRole,
      tenant: temporaryDomain,
      rawClaimsPayload: payload
    };

    return next();

  } catch (err) {
    console.error('[VoidMetric Middleware Boundary Breach] Execution terminated:', (err as Error).message);
    locals.user = null;
    
    return new Response(null, { 
      status: 302, 
      headers: {
        'Set-Cookie': 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
        'Location': '/login?error=session_invalidated_by_middleware'
      } 
    });
  }
});
