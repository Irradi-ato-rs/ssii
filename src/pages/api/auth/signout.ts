// src/pages/api/auth/signout.ts
export const prerender = false;

import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers'; // REQUIRED for Astro 6
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

  const domainCookie = cookies.get('auth_domain');
  
  // PASS env to getIdPConfigByDomain
  const config = domainCookie?.value ? await getIdPConfigByDomain(env, domainCookie.value) : null;

  clearAuthCookies(headers);

  const redirectUri = encodeURIComponent('https://ssii.fzoirm.com/login');

  if (config?.endSessionEndpoint) {
    // RP-Initiated Logout per the OIDC spec
    const separator = config.endSessionEndpoint.includes('?') ? '&' : '?';
    headers.append(
      'Location',
      `${config.endSessionEndpoint}${separator}post_logout_redirect_uri=${redirectUri}`
    );
  } else {
    // Fallback to local logout
    headers.append('Location', '/login');
  }

  return new Response(null, { status: 302, headers });
};   