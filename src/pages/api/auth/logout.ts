// src/pages/api/auth/logout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

export const GET: APIRoute = async ({ cookies }) => {
  // 1. Force clear the session token locally by dropping its lifetime to 0
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Point to the open OIDC global endpoint using exact template string interpolation syntax
  const corporatePostLogoutRedirectUri = encodeURIComponent('https://fzoirm.com');
  const externalFederatedLogoutTarget = `https://microsoftonline.com{corporatePostLogoutRedirectUri}`;

  return new Response(null, {
    status: 302,
    headers: {
      'Location': externalFederatedLogoutTarget
    }
  });
};
