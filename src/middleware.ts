// src/middleware.ts
import type { APIContext, MiddlewareNext } from 'astro';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { env } from 'cloudflare:workers';
import { getIdPConfigByDomain } from './config/tenants';

// Module-level JWKS cache (per-isolate) — kept for legacy JWT sessions
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

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

export async function onRequest(context: APIContext, next: MiddlewareNext) {
  const url = new URL(context.url);
  const pathParts = url.pathname.split('/').filter(Boolean);

  // Skip static assets
  if (url.pathname.startsWith('/_astro') || url.pathname === '/favicon.ico' || url.pathname.includes('.')) {
    return next();
  }

  // ─── PUBLIC ROUTES (no auth) ───
  const publicPaths = ['login', 'api/auth', 'api/register', 'portal', 'architecture', 'onboarding', 'documentation'];
  const isPublic = url.pathname === '/' || publicPaths.some(p => pathParts[0] === p || url.pathname.startsWith(`/${p}`));

  // ─── MAIN SESSION VERIFICATION ───
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
      // ── PRIMARY: KV session lookup (new opaque tokens) ──
      const sessionRaw = await env.VM_TENANT_DIRECTORY.get(`session:${sessionToken}`);

      if (sessionRaw) {
        const session = JSON.parse(sessionRaw);
        const role = await resolveRole(session.sub, env);
        context.locals.user = {
          sub: session.sub,
          email: session.email || '',
          tenant: session.tenantId,
          role,
        };
        return next();
      }

      // ── LEGACY FALLBACK: JWT validation (existing id_token sessions, expires in 24h) ──
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

      const role = await resolveRole(payload.sub, env);
      context.locals.user = {
        sub: payload.sub,
        email: payload.email || '',
        tenant: authDomain,
        role,
      };
      return next();

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
  if (pathParts[0] === 'portal' && pathParts.length === 2) {
    const requestedTenantId = pathParts[1];
    const sessionToken = context.cookies.get('aim_session_token')?.value;
    const authDomain = context.cookies.get('auth_domain')?.value;

    if (sessionToken && authDomain) {
      try {
        // ── PRIMARY: KV session lookup ──
        const sessionRaw = await env.VM_TENANT_DIRECTORY.get(`session:${sessionToken}`);

        if (sessionRaw) {
          const session = JSON.parse(sessionRaw);
          const user = {
            sub: session.sub,
            email: session.email || '',
            tenant: session.tenantId,
            role: await resolveRole(session.sub, env),
          };

          const portalRecord = await env.VM_TENANT_DIRECTORY.get(`portal:${requestedTenantId}`);
          if (!portalRecord) {
            return new Response('404 — Tenant not found', { status: 404 });
          }

          const { owner } = JSON.parse(portalRecord);
          if (owner !== user.sub) {
            return new Response('403 — Access denied', { status: 403 });
          }

          context.locals.user = user;
          context.locals.tenantId = requestedTenantId;
          context.locals.portalRecord = JSON.parse(portalRecord);
          return next();
        }

        // ── LEGACY FALLBACK: JWT validation ──
        const config = await getIdPConfigByDomain(env, authDomain);
        if (!config) {
          // No IdP config → self-serve path, let the page handle API-key auth
          return next();
        }

        const clientId = env[config.clientIdEnv]?.trim();
        const JWKS = getJwks(config.jwksUri);
        const verified = await jwtVerify(sessionToken, JWKS, {
          issuer: config.issuer,
          audience: clientId,
          algorithms: ['RS256', 'RS384', 'RS512'],
          clockTolerance: '60s',
        });

        const user = {
          sub: verified.payload.sub,
          email: verified.payload.email || '',
          tenant: authDomain,
          role: await resolveRole(verified.payload.sub, env),
        };

        const portalRecord = await env.VM_TENANT_DIRECTORY.get(`portal:${requestedTenantId}`);
        if (!portalRecord) {
          return new Response('404 — Tenant not found', { status: 404 });
        }

        const { owner } = JSON.parse(portalRecord);
        if (owner !== user.sub) {
          return new Response('403 — Access denied', { status: 403 });
        }

        context.locals.user = user;
        context.locals.tenantId = requestedTenantId;
        context.locals.portalRecord = JSON.parse(portalRecord);
        return next();

      } catch {
        return new Response('Internal error', { status: 500 });
      }
    }
    // No session → self-serve path, let the page handle API-key auth
    return next();
  }

  return next();
}   