// src/pages/api/auth/logout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

export const GET: APIRoute = async ({ cookies }) => {
  // 1. Force clear the session token by setting Max-Age to 0
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Redirect the browser back to the login gateway cleanly
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/login'
    }
  });
};
