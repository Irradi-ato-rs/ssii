// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { env } from 'cloudflare:workers';

export const onRequest = defineMiddleware(async (context, next) => {
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
    // No cookie found, user is not authenticated
    locals.user = null;
    return next();
  }

  try {
    // 2. Resolve Tenant Config to get JWKS URI (Optional: if multi-tenant)
    // For simplicity, assuming a single tenant or default JWKS URI for middleware
    // If multi-tenant, you might need to decode the JWT payload first (unsafe) to find the tenant,
    // or use a global JWKS URI if all tenants share the same Entra ID instance.
    
    // Assuming a single Entra ID instance for the app middleware:
    const issuer = env.ENTRA_ISSUER; // e.g., "https://login.microsoftonline.com/{tenant-id}/v2.0"
    const jwksUri = env.ENTRA_JWKS_URI; // e.g., "https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys"
    const audience = env.ENTRA_CLIENT_ID; // Your App Registration Client ID

    if (!issuer || !jwksUri || !audience) {
      console.error('Middleware: Missing Entra ID environment variables');
      locals.user = null;
      return next();
    }

    // 3. Verify the JWT Signature using JWKS
    const JWKS = createRemoteJWKSet(new URL(jwksUri));
    
    const { payload } = await jwtVerify(sessionCookie, JWKS, {
      issuer,
      audience,
      algorithms: ['RS256', 'RS384', 'RS512'],
    });

    // 4. Attach user data to locals
    // Entra ID ID Tokens typically contain: email, name, oid (object id), roles
    locals.user = {
      email: payload.email,
      name: payload.name,
      oid: payload.oid,
      role: payload.role || (payload.roles ? (Array.isArray(payload.roles) ? payload.roles[0] : payload.roles) : 'user'),
      // Attach full payload if needed for advanced claims
      ...payload 
    };

  } catch (error) {
    console.error('Middleware: JWT Verification Failed', error);
    locals.user = null;
    // Optional: Clear invalid cookie
    // context.cookies.set('aim_session_token', '', { maxAge: 0, path: '/' });
  }

  return next();
});   