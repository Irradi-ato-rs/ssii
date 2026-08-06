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

  // 2. Public Routes & CRITICAL Auth Callback Exclusion
  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];
  
  // EXPLICITLY EXCLUDE THE CALLBACK ROUTE
  // This MUST match your Entra ID Redirect URI path exactly to prevent loop
  //const isAuthCallback = 
    //url.pathname === '/api/auth/callback' || 
    //url.pathname.startsWith('/api/auth/')
    //url.pathname.startsWith('/api');
// REPLACE isAuthCallback:
const isApiRoute = 
  url.pathname === '/api/register' || 
  url.pathname === '/api/auth/callback' || 
  url.pathname.startsWith('/api/auth/');   
  
  //if (isAuthCallback || publicRoutes.includes(cleanPath)) {
    //return next();
  if (isApiRoute || publicRoutes.includes(cleanPath)) {
    return next();
  }

  // 3. Check Session
  const sessionToken = cookies.get('aim_session_token');

  if (!sessionToken || !sessionToken.value) {
    locals.user = null;
    // FIX: Manual Response to prevent cookie drop issues in Workers
    const headers = new Headers();
    headers.append('Location', '/?error=unauthenticated_session_gateway');
    return new Response(null, { status: 302, headers });
  }

  try {
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Middleware] KV Binding Missing');
      locals.user = null;
      // FIX: Manual Response
      const headers = new Headers();
      headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      headers.append('Location', '/?error=infrastructure_environment_fault');
      return new Response(null, { status: 302, headers });
    }

    // 4. Decode Domain
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed token');
    
    const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
    const userEmailClaim = rawEnvelopePayload.email || rawEnvelopePayload.sub || '';
    const extractedDomain = userEmailClaim.split('@').pop()?.toLowerCase();

    if (!extractedDomain) throw new Error('Missing domain');

    // 5. Fetch Config
    const serializedConfig = await tenantDirectory.get(`domain:${extractedDomain}`);
    if (!serializedConfig) {
      console.error(`[VoidMetric Middleware] Domain not found: ${extractedDomain}`);
      locals.user = null;
      // FIX: Manual Response
      const headers = new Headers();
      headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      headers.append('Location', '/?error=tenant_access_denied');
      return new Response(null, { status: 302, headers });
    }
    const targetConfig = JSON.parse(serializedConfig) as DynamicIdPConfig;

    const resolvedAudienceId = runtimeEnv?.[targetConfig.clientIdEnv]?.trim();
    if (!resolvedAudienceId) {
      locals.user = null;
      // FIX: Manual Response
      const headers = new Headers();
      headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      headers.append('Location', '/?error=configuration_runtime_fault');
      return new Response(null, { status: 302, headers });
    }

    // 6. Verify JWT
    const JWKS = createRemoteJWKSet(new URL(targetConfig.jwksUri));
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: targetConfig.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s'
    });

    // 7. Map Roles
    const directoryGroups = (payload.groups || payload.roles || []) as string[];
    let evaluatedRole: 'admin' | 'executive' | 'engineer' = 'engineer'; 

    if (directoryGroups.includes('VoidMetric_Admins') || directoryGroups.includes('Global_Admin')) {
      evaluatedRole = 'admin';
    } else if (directoryGroups.includes('VoidMetric_Executives') || directoryGroups.includes('C_Suite')) {
      evaluatedRole = 'executive';
    }

    locals.user = {
      email: userEmailClaim,
      role: evaluatedRole,
      tenant: extractedDomain,
      rawClaimsPayload: payload
    };

    return next();

  } catch (err) {
    console.error('[VoidMetric Middleware Fault] JWT validation aborted:', (err as Error).message);
    locals.user = null;
    
    // CRITICAL FIX: Manual Response for atomic cookie clear + redirect
    const responseHeaders = new Headers();
    responseHeaders.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    responseHeaders.append('Location', '/?error=session_invalidated_by_middleware');
    
    return new Response(null, { 
      status: 302, 
      headers: responseHeaders 
    });
  }
});   