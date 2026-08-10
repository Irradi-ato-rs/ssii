// src/pages/api/register.ts
export const prerender = false;

import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers'; // REQUIRED for Astro 6
import { getIdPConfig } from '../../config/tenants';

function parseEmailDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  const domain = email.slice(at + 1).toLowerCase().trim();
  if (!domain.includes('.')) return null;
  return domain;
}

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let str = '';
  for (const b of arr) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generatePkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
  const verifier = base64url(verifierBytes);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = base64url(digest);
  return { verifier, challenge };
}

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const POST: APIRoute = async ({ request }) => {
  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();

    if (!email || !email.includes('@')) {
      return jsonError('Invalid email address', 400);
    }

    const domain = parseEmailDomain(email);
    if (!domain) {
      return jsonError('Invalid email address', 400);
    }

    // PASS 'env' to getIdPConfig (now async)
    const config = await getIdPConfig(env, email);
    if (!config) {
      return jsonError('Unable to start sign-in for this account.', 403);
    }

    // Access secrets directly from imported 'env'
    const clientId = env[config.clientIdEnv]?.trim();
    const clientSecret = env[config.clientSecretEnv]?.trim();

    if (!clientId || !clientSecret) {
      console.error(`register: missing secret for domain=${domain}`);
      return jsonError('Sign-in is temporarily unavailable.', 500);
    }

    const nonce = crypto.randomUUID();
    const statePayload = { domain, nonce };
    const state = base64url(new TextEncoder().encode(JSON.stringify(statePayload)));

    const { verifier, challenge } = await generatePkcePair();

    const rigidRedirectUri = 'https://ssii.fzoirm.com/api/auth/callback';
    const cleanAuthBase = String(config.authorizationEndpoint).trim();

    const federationQueryParameters = new URLSearchParams({
      client_id: clientId,
      scope: 'openid profile email',
      response_type: 'code',
      state,
      nonce,
      login_hint: email,
      redirect_uri: rigidRedirectUri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    const finalOutboundHandshakeUrl =
      cleanAuthBase + (cleanAuthBase.includes('?') ? '&' : '?') + federationQueryParameters.toString();

    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    headers.append('Set-Cookie', `oidc_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);
    headers.append('Set-Cookie', `pkce_verifier=${verifier}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);

    console.log(`register: handshake initiated for domain=${domain}`);

    return new Response(JSON.stringify({ success: true, redirectUrl: finalOutboundHandshakeUrl }), {
      status: 200,
      headers,
    });
  } catch (error) {
    console.error('register: unhandled error', error);
    return jsonError('Sign-in failed. Please try again.', 500);
  }
};   