// src/pages/portal/[tenantId] — Self-serve tenant API (JSON, Bearer auth)
import type { APIContext } from 'astro';

export const prerender = false;

export const GET: APIContext['GET'] = async (ctx) => {
  const { params, request } = ctx;
  const { tenantId } = params;
  if (!tenantId) {
    return new Response(JSON.stringify({ error: 'Missing tenantId' }), { status: 400 });
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
  const apiKey = authHeader.split(' ')[1];

  const env = (ctx as any).env ?? (globalThis as any).env;

  const storedKey = await env.VM_TENANT_DIRECTORY.get(`apikey:${tenantId}`);
  if (!storedKey || apiKey !== storedKey) {
    return new Response(JSON.stringify({ error: 'Invalid key' }), { status: 401 });
  }

  const postureRaw = await env.VM_LIVE_POSTURE_CACHE.get(`posture:${tenantId}`);
  const posture = postureRaw ? JSON.parse(postureRaw) : null;
  const tenantName = await env.VM_TENANT_DIRECTORY.get(`tenantName:${tenantId}`) || 'Unknown';

  return new Response(JSON.stringify({
    tenant: tenantName,
    tenantId,
    lastScored: posture ? new Date(posture.timestamp * 1000).toISOString() : null,
    scores: posture || null,
  }), { headers: { 'Content-Type': 'application/json' } });
}; 