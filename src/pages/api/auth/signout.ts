// src/pages/api/auth/signout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// HARD ARCHITECTURAL RESET: SYSTEM DISCONNECT TERMINATION VECTOR v4
export const GET: APIRoute = async ({ cookies }) => {
  // 1. Evict the token context locally from browser storage
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Enforce absolute anti-caching headers to shatter the Back-Forward Cache (bfcache)
  const headers = new Headers();
  headers.append('Location', '/login');
  headers.append('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  headers.append('Pragma', 'no-cache');
  headers.append('Expires', '0');

  return new Response(null, {
    status: 302,
    headers
  });
};
