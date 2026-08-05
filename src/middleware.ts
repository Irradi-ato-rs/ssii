// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { jwtVerify, createRemoteJWKSet } from 'jose';

export const onRequest = defineMiddleware(async (context, next) => {
  // FIX: Dynamic import prevents Node.js build process from failing 
  // when prerendering static pages like about.astro
  const { env } = await import('cloudflare:workers');

  const { request, locals } = context;
  const url = new URL(request.url);

  // 1. Extract the ID Token from the 'aim_session_token' cookie
  const cookies = request.headers.get('Cookie') || '';
  const sessionCookie = cookies
    .split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('aim_session_token='))
    ?.split('=')[1];

  if (!sessionCookie) {
    locals.user = null;
    return next();
  }

  try {
    const issuer = env.ENTRA_ISSUER;
    const jwksUri = env.ENTRA_JWKS_URI;
    const audience = env.ENTRA_CLIENT_ID;

    if (!issuer || !jwksUri || !audience) {
      console.error('Middleware: Missing Entra ID environment variables');
      locals.user = null;
      return next();
    }

    // 2. Verify the JWT Signature using JWKS
    const JWKS = createRemoteJWKSet(new URL(jwksUri));
    
    const { payload } = await jwtVerify(sessionCookie, JWKS, {
      issuer,
      audience,
      algorithms: ['RS256', 'RS384', 'RS512'],
    });

    // 3. Attach user data to locals
    locals.user = {
      email: payload.email,
      name: payload.name,
      oid: payload.oid,
      role: payload.role || (payload.roles ? (Array.isArray(payload.roles) ? payload.roles[0] : payload.roles) : 'user'),
      ...payload 
    };

  } catch (error) {
    console.error('Middleware: JWT Verification Failed', error);
    locals.user = null;
  }

  return next();
});   