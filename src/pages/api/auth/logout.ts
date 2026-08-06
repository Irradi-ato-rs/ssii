// src/pages/api/auth/logout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// RECOMPILE_SIGNATURE: FORCE CLEAR V8 INSTANCE COMPILATION TARGET LAYER
export const GET: APIRoute = async ({ cookies }) => {
  // 1. Evict local edge session token
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Chained hard redirection string to explicitly resolve the NXDOMAIN bug
  const baseTarget = "https://fzoirm.com";
  const externalFederatedLogoutTarget = "https://microsoftonline.com" + encodeURIComponent(baseTarget);

  return new Response(null, {
    status: 302,
    headers: {
      'Location': externalFederatedLogoutTarget
    }
  });
};
