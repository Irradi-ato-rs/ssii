// src/pages/api/auth/signout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// LOCAL EXCLUSION ENGINE: RESET CONTEXT WITHOUT EXTERNAL DEPENDENCIES
export const GET: APIRoute = async ({ cookies }) => {
  // 1. Instantly evict the session token from the browser storage
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Redirect straight back to your clean login gateway locally
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/login'
    }
  });
};
