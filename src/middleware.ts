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

  // 1. Normalize Request Path For Uniform Evaluations
  let cleanPath = url.pathname;
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }
  // 2. HARD ASSET EXCLUSION MATRIX: Instantly short-circuit file payload checking
  const isStaticAsset = 
    url.pathname.startsWith('/_astro') || 
    url.pathname === '/favicon.ico' ||
    url.pathname.includes('.') || 
    url.pathname.startsWith('/@vite') ||
    url.pathname.startsWith('/src/');

  if (isStaticAsset) {
    return next();
  }

  // 3. EXPLICIT LITERAL ROUTE MATCHING BOUNDARY
  // Prevents relative route directory traversals (e.g. /api/auth/../../portal)
  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];
  const explicitApiRoutes = [
    '/api/register',
    '/api/auth/callback',
    '/api/auth/signout'
  ];

  if (explicitApiRoutes.includes(url.pathname) || publicRoutes.includes(cleanPath)) {
    return next();
  }
  // 4. Check Session Token Existence
  const sessionToken = cookies.get('aim_session_token');

  if (!sessionToken || !sessionToken.value) {
    locals.user = null;
    const headers = new Headers();
    headers.append('Location', '/login?error=unauthenticated_session_gateway');
    return new Response(null, { status: 302, headers });
  }
  try {
    const runtimeEnv = locals.runtime?.env;
    const tenantDirectory = runtimeEnv?.VM_TENANT_DIRECTORY;

    if (!tenantDirectory) {
      console.error('[VoidMetric Middleware] KV Key Namespace Binding Missing');
      locals.user = null;
      const headers = new Headers();
      headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      headers.append('Location', '/login?error=infrastructure_environment_fault');
      return new Response(null, { status: 302, headers });
    }

    // 5. CRYPTOGRAPHIC ISOLATION PRE-PARSING
    // Treat string values as fully unverified data vectors until signature step passes
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed token envelope structural chunks');
    
    let temporaryDomain = '';
    try {
      const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
      const userEmailClaim = rawEnvelopePayload.email || rawEnvelopePayload.sub || '';
      temporaryDomain = userEmailClaim.split('@').pop()?.toLowerCase() || '';
    } catch {
      throw new Error('Invalid base64 payload serialization envelope parsing fault');
    }

    if (!temporaryDomain) throw new Error('Missing identity routing origin domain key claim');

    // 6. Fetch Private Key Vault Identity Matrix Configuration
    const serializedConfig = await tenantDirectory.get(`domain:${temporaryDomain}`);
    if (!serializedConfig) {
      console.error(`[VoidMetric Middleware] Unregistered Domain Entry Vector: ${temporaryDomain}`);
      locals.user = null;
      const headers = new Headers();
      headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      headers.append('Location', '/login?error=tenant_access_denied');
      return new Response(null, { status: 302, headers });
    }
    const targetConfig = JSON.parse(serializedConfig) as DynamicIdPConfig;
    const resolvedAudienceId = runtimeEnv?.[targetConfig.clientIdEnv]?.trim();
    if (!resolvedAudienceId) {
      locals.user = null;
      const headers = new Headers();
      headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      headers.append('Location', '/login?error=configuration_runtime_fault');
      return new Response(null, { status: 302, headers });
    }

    // 7. CRYPTOGRAPHIC SIGNATURE-FIRST AUTHORIZATION
    const JWKS = createRemoteJWKSet(new URL(targetConfig.jwksUri));
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: targetConfig.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s'
    });

    // 8. IN-FLIGHT EXPIRATION HARD ASSERTION
    // Extinguishes token replay or hijacking vectors at the edge boundary
    const currentUnixTimestamp = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < currentUnixTimestamp) {
      throw new Error('Federated identity token payload lifecycle validity period expired');
    }

    // 9. Assign Authenticated Security Roster Roles Natively
    const validatedEmail = (payload.email || payload.sub || '') as string;
    const directoryGroups = (payload.groups || payload.roles || []) as string[];
    let evaluatedRole: 'admin' | 'executive' | 'engineer' = 'engineer'; 

    if (directoryGroups.includes('VoidMetric_Admins') || directoryGroups.includes('Global_Admin')) {
      evaluatedRole = 'admin';
    } else if (directoryGroups.includes('VoidMetric_Executives') || directoryGroups.includes('C_Suite')) {
      evaluatedRole = 'executive';
    }

    locals.user = {
      email: validatedEmail,
      role: evaluatedRole,
      tenant: temporaryDomain,
      rawClaimsPayload: payload
    };

    return next();

  } catch (err) {
    console.error('[VoidMetric Middleware Boundary Breach] Context dropped:', (err as Error).message);
    locals.user = null;
    
    const responseHeaders = new Headers();
    responseHeaders.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    responseHeaders.append('Location', '/login?error=session_invalidated_by_middleware');
    
    return new Response(null, { 
      status: 302, 
      headers: responseHeaders 
    });
  }
});
