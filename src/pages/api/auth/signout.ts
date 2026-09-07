// src/pages/api/auth/signout.ts
export const prerender = false;

import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { getIdPConfigByDomain } from '../../../config/tenants';

function clearAuthCookies(headers: Headers) {
  headers.append('Set-Cookie', 'aim_session_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  headers.append('Set-Cookie', 'auth_domain=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  headers.append('Set-Cookie', 'oidc_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  headers.append('Set-Cookie', 'pkce_verifier=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
}

export const POST: APIRoute = async ({ cookies }) => {
  const headers = new Headers();
  headers.append('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  headers.append('Pragma', 'no-cache');
  headers.append('Expires', '0');

  // 1. Delete KV session record (SESSION namespace — immediate invalidation)
  const sessionToken = cookies.get('aim_session_token')?.value;
  if (sessionToken) {
    try {
      await env.SESSION.delete(`session:${sessionToken}`);
    } catch {
      // Non-fatal: session will expire via TTL regardless
    }
  }

  // 2. Resolve IdP for RP-Initiated Logout
  const domainCookie = cookies.get('auth_domain');
  const config = domainCookie?.value ? await getIdPConfigByDomain(env, domainCookie.value) : null;

  // 3. Clear all auth cookies
  clearAuthCookies(headers);

  // 4. Redirect
  const redirectUri = encodeURIComponent('https://ssii.fzoirm.com/login');

  if (config?.endSessionEndpoint) {
    const separator = config.endSessionEndpoint.includes('?') ? '&' : '?';
    headers.append(
      'Location',
      `${config.endSessionEndpoint}${separator}post_logout_redirect_uri=${redirectUri}`
    );
  } else {
    headers.append('Location', '/login');
  }

  return new Response(null, { status: 302, headers });
};   