// src/pages/api/auth/logout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// CACHE_BUST_ID: 1785989201999 -- FORCE TOTAL CLOUDFLARE EDGE RECOMPILATION
export const GET: APIRoute = async ({ cookies }) => {
  // 1. Force clear the session token locally by dropping its lifetime to 0
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Clear variable interpolation using explicit absolute string chaining
  const returnTarget = "https://fzoirm.com";
  const externalFederatedLogoutTarget = "https://microsoftonline.com" + encodeURIComponent(returnTarget);

  return new Response(null, {
    status: 302,
    headers: {
      'Location': externalFederatedLogoutTarget
    }
  });
};
