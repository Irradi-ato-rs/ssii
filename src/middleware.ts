// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { env } from 'cloudflare:workers'; // REQUIRED for Astro 6
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { getIdPConfigByDomain } from './config/tenants';

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(jwksUri: string) {
  let jwks = jwksCache.get(jwksUri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    jwksCache.set(jwksUri, jwks);
  }
  return jwks;
}

function parseEmailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return '';
  return email.slice(at + 1).toLowerCase().trim();
}

function resolveRole(
  email: string,
  roleAllowlistRaw: string | undefined
): 'governance' | 'admin' | 'executive' | 'engineer' {
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
  return 'engineer';
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { request, locals, cookies } = context;
  const url = new URL(request.url);

  let cleanPath = url.pathname;
  if (cleanPath.length > 1 && cleanPath.endsWith('/')) {
    cleanPath = cleanPath.slice(0, -1);
  }

  if (url.pathname.startsWith('/_astro') || url.pathname === '/favicon.ico' || url.pathname.includes('.')) {
    return next();
  }

  const publicRoutes = ['/', '/login', '/architecture', '/onboarding'];
  const explicitApiRoutes = ['/api/register', '/api/auth/callback', '/api/auth/signout'];
  if (explicitApiRoutes.includes(url.pathname) || publicRoutes.includes(cleanPath)) {
    return next();
  }

  const sessionToken = cookies.get('aim_session_token');
  if (!sessionToken?.value) {
    return context.redirect('/login?error=unauthenticated_session_gateway');
  }

  try {
    const tokenChunks = sessionToken.value.split('.');
    if (tokenChunks.length !== 3) throw new Error('Malformed token');

    const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
    const validatedEmail = (rawEnvelopePayload.email || '') as string;
    if (!validatedEmail) throw new Error('missing_email_claim');

    // Get config from KV (PASS env, use domain lookup)
    const domain = parseEmailDomain(validatedEmail);
    const config = await getIdPConfigByDomain(env, domain); // Changed
    if (!config) throw new Error('unauthorized_domain');

    // Access secrets from imported env (NOT locals.runtime)
    const resolvedAudienceId = env[config.clientIdEnv]?.trim(); // Changed
    if (!resolvedAudienceId) throw new Error('configuration_fault');

    const JWKS = getJwks(config.jwksUri);
    const { payload } = await jwtVerify(sessionToken.value, JWKS, {
      issuer: config.issuer,
      audience: resolvedAudienceId,
      algorithms: ['RS256', 'RS384', 'RS512'],
      clockTolerance: '30s',
    });

    // Access role allowlist from imported env
    const evaluatedRole = resolveRole(validatedEmail, env.PRIVATE_ROLE_ALLOWLIST); // Changed

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
    return context.redirect('/login?error=session_invalidated_by_middleware');
  }
});   