// src/middleware.ts
import type { APIContext } from 'astro';

export async function middleware(context: APIContext) {
  const url = new URL(context.url);
  const pathParts = url.pathname.split('/').filter(Boolean);

  // ─── PUBLIC ROUTES (no auth) ───
  const publicPaths = ['login', 'api/auth', 'api/register'];
  const isPublic = publicPaths.some(p => pathParts[0] === p || url.pathname.startsWith(`/${p}`));

  // ─── OIDC SESSION VERIFICATION ───
  if (!isPublic) {
    const sessionToken = context.cookies.get('voidmetric_session')?.value;

    if (!sessionToken) {
      if (pathParts[0] === 'api') {
        return new Response(JSON.stringify({ error: 'unauthenticated' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return context.redirect(`/login?error=unauthenticated_session_gateway`);
    }

    try {
      const env = (context as any).env;
      const decoded = await verifySessionToken(sessionToken, env.PRIVATE_SESSION_SECRET);
      if (!decoded) {
        if (pathParts[0] === 'api') {
          return new Response(JSON.stringify({ error: 'invalid_session' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return context.redirect(`/login?error=expired_session`);
      }

      // Resolve role from VoidMetric-controlled allow-list
      const role = await resolveRole(decoded.sub, env);
      context.locals.user = {
        sub: decoded.sub,
        email: decoded.email,
        tenant: decoded.tenant,
        role,
      };
    } catch {
      if (pathParts[0] === 'api') {
        return new Response(JSON.stringify({ error: 'session_error' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return context.redirect(`/login?error=session_error`);
    }
  }

  // ─── PORTAL TENANT OWNERSHIP CHECK ───
  // /portal/:tenantId — adapter operator page
  if (pathParts[0] === 'portal' && pathParts.length === 2) {
    const requestedTenantId = pathParts[1];
    const user = context.locals.user;

    if (!user) {
      return context.redirect(`/login?error=unauthenticated_session_gateway`);
    }

    // Check ownership: portal:{tenantId}.owner must match user.sub
    try {
      const env = (context as any).env || (await (context as any).getEnv?.());
      const portalRecord = env?.VM_TENANT_DIRECTORY
        ? await env.VM_TENANT_DIRECTORY.get(`portal:${requestedTenantId}`)
        : null;

      if (!portalRecord) {
        return new Response('404 — Tenant not found', { status: 404 });
      }

      const { owner } = JSON.parse(portalRecord);
      if (owner !== user.sub) {
        return new Response('403 — Access denied', { status: 403 });
      }

      // Attach tenantId to locals for the page
      context.locals.tenantId = requestedTenantId;
      context.locals.portalRecord = JSON.parse(portalRecord);
    } catch {
      return new Response('500 — Portal lookup failed', { status: 500 });
    }
  }

  return context.next();
}

// ─── HELPERS ──────────────────────────────────────────────────────────────

async function verifySessionToken(
  token: string,
  secret: string
): Promise<{ sub: string; email: string; tenant: string } | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const dataToVerify = `${header}.${payload}`;

  // Verify HMAC-SHA256 signature
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const sigBytes = Uint8Array.from(
      atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      new TextEncoder().encode(dataToVerify)
    );

    if (!valid) return null;
  } catch {
    return null;
  }

  // Decode payload
  try {
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    if (decoded.exp && decoded.exp < Date.now() / 1000) return null;
    return { sub: decoded.sub, email: decoded.email, tenant: decoded.tenant };
  } catch {
    return null;
  }
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