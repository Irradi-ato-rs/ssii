// src/pages/api/auth/signout.ts
import type { APIRoute } from 'astro';

export const prerender = false;

// UNIQUE CACHE BUSTER ID: FORCE REDEPLOYMENT STRATIFICATION 9999122
export const GET: APIRoute = async ({ cookies }) => {
  let microsoftTenantId = 'common';

  const sessionToken = cookies.get('aim_session_token');
  if (sessionToken && sessionToken.value) {
    try {
      const tokenChunks = sessionToken.value.split('.');
      if (tokenChunks.length === 3) {
        // Correctly handle base64url padding for atob processing
        let base64Payload = tokenChunks[1].replace(/-/g, '+').replace(/_/g, '/');
        while (base64Payload.length % 4) {
          base64Payload += '=';
        }
        const rawEnvelopePayload = JSON.parse(atob(base64Payload));
        if (rawEnvelopePayload.tid) {
          microsoftTenantId = String(rawEnvelopePayload.tid).trim();
        }
      }
    } catch (e) {
      console.error('[VoidMetric Signout Crypto Fault] JWT claim extraction failed:', e);
      microsoftTenantId = 'common';
    }
  }

  // Evict tracking session token locally
  cookies.set('aim_session_token', '', {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 0
  });

  // Construct absolute URL via native Web API objects to enforce safe slashes
  const targetUrl = new URL(`https://microsoftonline.com{microsoftTenantId}/oauth2/v2.0/logout`);
  targetUrl.searchParams.set('post_logout_redirect_uri', 'https://fzoirm.com');

  return new Response(null, {
    status: 302,
    headers: {
      'Location': targetUrl.toString()
    }
  });
};
