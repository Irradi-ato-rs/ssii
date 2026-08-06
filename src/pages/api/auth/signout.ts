// src/pages/api/auth/signout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

export const GET: APIRoute = async ({ cookies, locals }) => {
  // 1. Evict the local token
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 2. Construct Azure Logout URL
  // 'post_logout_redirect_uri' must be registered in Azure App Registration > Authentication
  const azureLogoutEndpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/logout';
  const redirectUri = encodeURIComponent('https://ssii.fzoirm.com/login');
  
  const headers = new Headers();
  headers.append('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  headers.append('Pragma', 'no-cache');
  headers.append('Expires', '0');
  
  // Redirect to Azure to kill the SSO session, then bounce back to your login page
  headers.append('Location', `${azureLogoutEndpoint}?post_logout_redirect_uri=${redirectUri}`);

  return new Response(null, {
    status: 302,
    headers
  });
};   