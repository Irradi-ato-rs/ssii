// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
// Importing 'jose' is fine, it's universal.
import { jwtVerify, createRemoteJWKSet } from 'jose'; 

export const onRequest = defineMiddleware(async (context, next) => {
  // DYNAMIC IMPORT: Move cloudflare:workers import inside the function
  // This prevents the build process from trying to resolve it during static generation
  const { env } = await import('cloudflare:workers');
  
  const { request, locals } = context;
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
      locals.user = null;
      return next();
    }

    const JWKS = createRemoteJWKSet(new URL(jwksUri));
    
    const { payload } = await jwtVerify(sessionCookie, JWKS, {
      issuer,
      audience,
      algorithms: ['RS256', 'RS384', 'RS512'],
    });

    locals.user = {
      email: payload.email,
      name: payload.name,
      oid: payload.oid,
      role: payload.role || (payload.roles ? (Array.isArray(payload.roles) ? payload.roles[0] : payload.roles) : 'user'),
    };

  } catch (error) {
    console.error('Middleware: JWT Verification Failed', error);
    locals.user = null;
  }

  return next();
});   