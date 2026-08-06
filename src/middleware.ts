// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfig } from './config/tenants';

export const onRequest = defineMiddleware(async (context, next) => {
  const { request, locals, cookies } = context;
  const url = new URL(request.url);

  let cleanPath = url.pathname;
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  // Asset Bypass Matrix
  if (url.pathname.startsWith('/_astro') || url.pathname === '/favicon.ico' || url.pathname.includes('.')) {
    return next();
  }

  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];
  const explicitApiRoutes = ['/api/register', '/api/auth/callback', '/api/auth/signout'];

  if (explicitApiRoutes.includes(url.pathname) || publicRoutes.includes(cleanPath)) {
    return next();
  }

  const sessionToken = cookies.get('aim_session_token');
  if (!sessionToken || !sessionToken.value) {
    return context.redirect('/login?error=unauthenticated_session_gateway');
  }

  try {
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed token');
    
    const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
    const validatedEmail = (rawEnvelopePayload.email || rawEnvelopePayload.sub || '') as string;
    
    // Aligned to look up tenant matrix from static configuration files uniformly
    const config = getIdPConfig(validatedEmail);
    if (!config) throw new Error('unauthorized_domain');

    const runtimeEnv = locals.runtime?.env || (globalThis as any).process?.env || {};
    const resolvedAudienceId = runtimeEnv[config.clientIdEnv]?.trim();

    if (!resolvedAudienceId) throw new Error('configuration_fault');

    const JWKS = createRemoteJWKSet(new URL(config.jwksUri));
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: config.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s'
    });

    const directoryGroups = (payload.groups || payload.roles || []) as string[];
    let evaluatedRole: 'admin' | 'executive' | 'engineer' = 'engineer'; 

    if (directoryGroups.includes('VoidMetric_Admins') || directoryGroups.includes('Global_Admin')) {
      evaluatedRole = 'admin';
    }

    locals.user = {
      email: validatedEmail,
      role: evaluatedRole,
      tenant: validatedEmail.split('@')[1] || '',
      rawClaimsPayload: payload
    };

    return next();

  } catch (err) {
    console.error('[VoidMetric Guard Loop Exception]:', (err as Error).message);
    cookies.delete('aim_session_token', { path: '/' });
    return context.redirect('/login?error=session_invalidated_by_middleware');
  }
});
