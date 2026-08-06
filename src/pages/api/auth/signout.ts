// src/pages/api/auth/signout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

export const GET: APIRoute = async ({ cookies }) => {
  const sessionToken = cookies.get('aim_session_token');
  let microsoftTenantId = 'common'; 

  if (sessionToken && sessionToken.value) {
    try {
      const tokenChunks = sessionToken.value.split('.');
      if (tokenChunks.length === 3) {
        const rawEnvelopePayload = JSON.parse(atob(tokenChunks[1]));
        if (rawEnvelopePayload.tid) {
          microsoftTenantId = String(rawEnvelopePayload.tid).trim();
        }
      }
    } catch {
      microsoftTenantId = 'common';
    }
  }

  // Clear cookie local instance
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // Explicit string generation using clean separate declarations to bypass caching bugs
  const domainPrefix = "https://microsoftonline.com";
  const querySuffix = "/oauth2/v2.0/logout?post_logout_redirect_uri=";
  const destinationTarget = encodeURIComponent("https://fzoirm.com");

  const externalFederatedLogoutTarget = domainPrefix + microsoftTenantId + querySuffix + destinationTarget;

  return new Response(null, {
    status: 302,
    headers: {
      'Location': externalFederatedLogoutTarget
    }
  });
};
