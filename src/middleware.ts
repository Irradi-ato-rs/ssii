// src/middleware.ts
import type { APIContext } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { env } from 'cloudflare:workers';
import { getIdPConfigByDomain } from './config/tenants';

// Module-level JWKS cache (per-isolate)
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

export async function onRequest(context: APIContext) {
  const url = new URL(context.url);
  const pathParts = url.pathname.split('/').filter(Boolean);

  // ─── PUBLIC ROUTES (no auth) ───
  const publicPaths = ['login', 'api/auth', 'api/register', 'portal'];
  const isPublic = publicPaths.some(p => pathParts[0] === p || url.pathname.startsWith(`/${p}`));

  // ─── OIDC SESSION VERIFICATION ───
  if (!isPublic) {
    const sessionToken = context.cookies.get('aim_session_token')?.value;
    const authDomain = context.cookies.get('auth_domain')?.value;

    if (!sessionToken || !authDomain) {
      if (pathParts[0] === 'api') {
        return new Response(JSON.stringify({ error: 'unauthenticated' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return context.redirect('/login?error=unauthenticated_session_gateway');
    }

    try {
      // Resolve tenant IdP config
      const config = await getIdPConfigByDomain(env, authDomain);
      if (!config) {
        if (pathParts[0] === 'api') {
          return new Response(JSON.stringify({ error: 'invalid_session' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return context.redirect('/login?error=expired_session');
      }

      // Verify IdP JWT against JWKS
      const clientId = env[config.clientIdEnv]?.trim();
      const JWKS = getJwks(config.jwksUri);

      let payload: any;
      try {
        const verified = await jwtVerify(sessionToken, JWKS, {
          issuer: config.issuer,
          audience: clientId,
          algorithms: ['RS256', 'RS384', 'RS512'],
          clockTolerance: '60s',
        });
        payload = verified.payload;
      } catch {
        if (pathParts[0] === 'api') {
          return new Response(JSON.stringify({ error: 'invalid_session' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return context.redirect('/login?error=expired_session');
      }

      // Resolve role from VoidMetric-controlled allow-list
      const role = await resolveRole(payload.sub, env);
      context.locals.user = {
        sub: payload.sub,
        email: payload.preferred_username || payload.email || '',
        tenant: authDomain,
        role,
      };
    } catch {
      if (pathParts[0] === 'api') {
        return new Response(JSON.stringify({ error: 'session_error' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return context.redirect('/login?error=session_error');
    }
  }

  // ─── PORTAL TENANT OWNERSHIP CHECK (enterprise path only) ───
  // Only fires when an OIDC session exists. Self-serve (API-key) requests
  // have no session, so this block is skipped and the page handles its own auth.
  if (pathParts[0] === 'portal' && pathParts.length === 2 && context.locals.user) {
    const requestedTenantId = pathParts[1];
    const user = context.locals.user;

    try {
      const portalRecord = env.VM_TENANT_DIRECTORY
        ? await env.VM_TENANT_DIRECTORY.get(`portal:${requestedTenantId}`)
        : null;

      if (!portalRecord) {
        return new Response('404 — Tenant not found', { status: 404 });
      }

      const { owner } = JSON.parse(portalRecord);
      if (owner !== user.sub) {
        return new Response('403 — Access denied', { status: 403 });
      }

      context.locals.tenantId = requestedTenantId;
      context.locals.portalRecord = JSON.parse(portalRecord);
    } catch {
      return new Response('500 — Portal lookup failed', { status: 500 });
    }
  }

  return context.next();
}

// ─── HELPERS ──────────────────────────────────────────────────────────────

async function resolveRole(sub: string, env: any): Promise<string> {
  try {
    const record = await env.VM_TENANT_DIRECTORY?.get(`roles:${sub}`);
    if (!record) return 'operator';
    const { role } = JSON.parse(record);
    const allowed = (env.PRIVATE_ROLE_ALLOWLIST || '').split(',').map((r: string) => r.trim());
    return allowed.includes(role) ? role : 'operator';
  } catch {
    return 'operator';
  }
}   