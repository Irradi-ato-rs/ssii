// src/pages/api/auth/logout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

export const GET: APIRoute = async ({ cookies }) => {
  // 1. Peek inside the current session token to discover the real Microsoft tenant context
  const sessionToken = cookies.get('aim_session_token');
  let microsoftTenantId = 'common'; // Fallback variable parameter

  if (sessionToken && sessionToken.value) {
    try {
      const tokenChunks = sessionToken.value.split('.');
      if (tokenChunks.length === 3) {
        const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
        // Extract the original Entra ID Directory Tenant ID claim safely
        if (rawEnvelopePayload.tid) {
          microsoftTenantId = rawEnvelopePayload.tid;
        }
      }
    } catch {
      // Graceful fallback to common pool context on parsing failure
      microsoftTenantId = 'common';
    }
  }

  // 2. Force clear the session token locally by dropping its lifetime to 0
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // 3. Build the absolute target destination url using string addition to prevent edge parsing glitches
  const baseReturnTarget = "https://fzoirm.com";
  const externalFederatedLogoutTarget = "https://microsoftonline.com" + microsoftTenantId + "/oauth2/v2.0/logout?post_logout_redirect_uri=" + encodeURIComponent(baseReturnTarget);

  return new Response(null, {
    status: 302,
    headers: {
      'Location': externalFederatedLogoutTarget
    }
  });
};
