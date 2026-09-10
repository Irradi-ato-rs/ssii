// src/pages/api/register.ts
export const prerender = false;

import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { getIdPConfig } from '../../config/tenants';

const VALID_MODES = ['login', 'register'] as const;
type Mode = (typeof VALID_MODES)[number];

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
  if (!env) {
    console.error('FATAL: Global cloudflare:workers env is undefined.');
    return jsonError('Server configuration error', 500);
  }

  try {
    const formData = await request.formData();
    const email = formData.get('email')?.toString().trim();
    const rawMode = formData.get('mode')?.toString() || 'login';
    const mode: Mode = (VALID_MODES as readonly string[]).includes(rawMode)
      ? (rawMode as Mode)
      : 'login';

    if (!email || !email.includes('@')) {
      return jsonError('Invalid email address', 400);
    }

    const domain = parseEmailDomain(email);
    if (!domain) {
      return jsonError('Invalid email address', 400);
    }

    // ─── SELF-SERVE PATH (no enterprise KV record) ───────────────────────────
    const tenantRecord = await env.VM_TENANT_DIRECTORY.get(`tenant:${domain}`);
    console.log(`[register] KV lookup: tenant:${domain} → ${tenantRecord ? 'FOUND' : 'MISSING'}`);

    if (!tenantRecord) {
      const tenantId = domain;
      const roleKey = `roles:${email}`;
      const existingRole = await env.VM_TENANT_DIRECTORY.get(roleKey);

      if (mode === 'login' && !existingRole) {
        return jsonError('Account not found. Please register first.', 404);
      }

      // Mint API key if absent
      let apiKey = await env.VM_TENANT_DIRECTORY.get(`apikey:${tenantId}`);
      if (!apiKey) {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        apiKey = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        await env.VM_TENANT_DIRECTORY.put(`apikey:${tenantId}`, apiKey);
        console.log(`[register] Minted API key for self-serve tenant=${tenantId}`);
      }

      // Role (default: operator)
      if (!existingRole) {
        await env.VM_TENANT_DIRECTORY.put(roleKey, JSON.stringify({ role: 'operator' }));
      }

      // Tenant name
      if (!(await env.VM_TENANT_DIRECTORY.get(`tenantName:${tenantId}`))) {
        await env.VM_TENANT_DIRECTORY.put(`tenantName:${tenantId}`, tenantId);
      }

      // Session
      const sessionToken = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
      await env.SESSION.put(`session:${sessionToken}`, JSON.stringify({
        sub: email,
        tenantId,
        role: 'operator',
        email,
        createdAt: Date.now(),
      }), { expirationTtl: 86400 });

      const headers = new Headers();
      headers.set('Content-Type', 'application/json');
      headers.append('Set-Cookie', `aim_session_token=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
      headers.append('Set-Cookie', `auth_domain=${tenantId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);

      console.log(`[register] Self-serve session established: email=${email} tenant=${tenantId} mode=${mode}`);

      return new Response(JSON.stringify({ success: true, redirectUrl: `/integrity-adapters?tenant=${tenantId}` }), {
        status: 200,
        headers,
      });
    }

    // ─── ENTERPRISE / LOGIN PATH (full OIDC) ─────────────────────────────────
    const config = await getIdPConfig(env, email);
    if (!config) {
      return jsonError('Unable to start sign-in for this account.', 403);
    }

    const clientId = env[config.clientIdEnv]?.trim();
    if (!clientId) {
      console.error(`register: missing client_id for domain=${domain}`);
      return jsonError('Sign-in is temporarily unavailable.', 500);
    }

    const nonce = crypto.randomUUID();
    const statePayload = { domain, nonce, mode };
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

    console.log(`[register] OIDC handshake initiated for domain=${domain} mode=${mode}`);

    return new Response(JSON.stringify({ success: true, redirectUrl: finalOutboundHandshakeUrl }), {
      status: 200,
      headers,
    });

  } catch (error) {
    console.error('register: unhandled error', error);
    return jsonError('Sign-in failed. Please try again.', 500);
  }
};   