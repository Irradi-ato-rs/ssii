// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { env } from 'cloudflare:workers';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfigByDomain } from './config/tenants';

// --- Helper: JWKS Cache ---
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

// --- Helper: Parse Domain ---
function parseEmailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return '';
  return email.slice(at + 1).toLowerCase().trim();
}

// --- Helper: Hybrid Role Resolution (Claims + Allowlist) ---
function resolveRole(
  email: string,
  roleAllowlistRaw: string | undefined,
  idpClaims: any
): 'governance' | 'admin' | 'executive' | 'engineer' {
  
  // 1. PRIORITY: Check IDP Claims (Entra ID / Okta Groups/Roles)
  // Adjust claim keys ('roles', 'groups', 'extension_role') based on your IdP config
  const roles = idpClaims?.roles || idpClaims?.groups || idpClaims?.extension_role || [];
  
  if (Array.isArray(roles)) {
    // Map specific IdP group names to VoidMetric roles
    if (roles.some((r: string) => r.includes('Governance') || r === 'void-governance')) return 'governance';
    if (roles.some((r: string) => r.includes('Admin') || r === 'void-admin')) return 'admin';
    if (roles.some((r: string) => r.includes('Executive') || r === 'void-executive')) return 'executive';
    if (roles.some((r: string) => r.includes('Engineer') || r === 'void-engineer')) return 'engineer';
  }

  // 2. FALLBACK: Manual Allowlist (if no valid claim found)
  const normalizedEmail = email.toLowerCase();
  if (roleAllowlistRaw) {
    try {
      const allowlist = JSON.parse(roleAllowlistRaw) as Record<string, string[]>;
      for (const role of ['governance', 'admin', 'executive', 'engineer'] as const) {
        if (allowlist[role]?.some((e) => e.toLowerCase() === normalizedEmail)) {
          return role;
        }
      }
    } catch {
      console.error('[VoidMetric Guard] Malformed PRIVATE_ROLE_ALLOWLIST');
    }
  }

  // 3. DEFAULT
  return 'engineer';
}

// --- Middleware Logic ---
export const onRequest = defineMiddleware(async (context, next) => {
  const { request, locals, cookies } = context;
  const url = new URL(request.url);

  let cleanPath = url.pathname;
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  // Skip static assets
  if (url.pathname.startsWith('/_astro') || url.pathname === '/favicon.ico' || url.pathname.includes('.')) {
    return next();
  }

  // Public & API Routes
  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];
  const explicitApiRoutes = ['/api/register', '/api/auth/callback', '/api/auth/signout'];
  if (explicitApiRoutes.includes(url.pathname) || publicRoutes.includes(cleanPath)) {
    return next();
  }

  // Session Validation
  const sessionToken = cookies.get('aim_session_token');
  if (!sessionToken?.value) {
    locals.user = null;
    return context.redirect('/login?error=unauthenticated_session_gateway');
  }

  try {
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed token');

    const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
    const validatedEmail = (rawEnvelopePayload.email || '') as string;
    if (!validatedEmail) throw new Error('missing_email_claim');

    const domain = parseEmailDomain(validatedEmail);
    
    // Pass env to KV lookup
    const config = await getIdPConfigByDomain(env, domain);
    if (!config) throw new Error('unauthorized_domain');

    // Access secrets from imported env
    const resolvedAudienceId = env[config.clientIdEnv]?.trim();
    if (!resolvedAudienceId) throw new Error('configuration_fault');

    const JWKS = getJwks(config.jwksUri);
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: config.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s',
    });

    // Hybrid Role Resolution
    const evaluatedRole = resolveRole(validatedEmail, env.PRIVATE_ROLE_ALLOWLIST, payload);

    locals.user = {
      email: validatedEmail,
      role: evaluatedRole,
      tenant: domain,
      rawClaimsPayload: payload,
    };

    return next();
  } catch (err) {
    console.error('[VoidMetric Guard Loop Exception]:', (err as Error).message);
    cookies.delete('aim_session_token', { path: '/' });
    locals.user = null;
    return context.redirect('/login?error=session_invalidated_by_middleware');
  }
});   