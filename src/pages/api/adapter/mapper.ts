// src/pages/api/adapter/mapper.ts
// Governance/admin exclusive: test and commit adapter configs.
// Same auth model as /api/governance/sandbox.
import type { APIContext } from 'astro';
import { normalizeWithConfig } from '../../../lib/normalize-with-config';
import { aggregateToMatrix } from '../../../lib/aggregate-to-matrix';
import { validateAdapterConfig, type AdapterConfig } from '../../../lib/adapter-config';

export const prerender = false;

export const POST: APIContext['POST'] = async ({ request, locals, env }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
  if (locals.user.role !== 'governance' && locals.user.role !== 'admin') {
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 });
  }

  try {
    const { tenantId, action, rawPayload, adapterConfig } = await request.json();

    if (!tenantId || typeof tenantId !== 'string') {
      return new Response(JSON.stringify({ error: 'Missing tenantId' }), { status: 400 });
    }

    // ─── TENANT SCOPING ─────────────────────────────────────────────────────
    if (locals.user.role === 'admin' && locals.user.tenant !== tenantId) {
      return new Response(
        JSON.stringify({ error: `Tenant ${tenantId} is outside your scope` }),
        { status: 403 }
      );
    }
    // ─────────────────────────────────────────────────────────────────────────

    if (action === 'load') {
      const raw = await env.VM_TENANT_DIRECTORY.get(`adapter:${tenantId}`);
      return new Response(
        JSON.stringify({ adapterConfig: raw ? JSON.parse(raw) : null }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (action === 'test') {
      if (!adapterConfig) {
        return new Response(JSON.stringify({ error: 'adapterConfig required for test' }), { status: 400 });
      }
      const vErr = validateAdapterConfig(adapterConfig);
      if (vErr) {
        return new Response(JSON.stringify({ error: vErr }), { status: 400 });
      }
      if (!rawPayload) {
        return new Response(JSON.stringify({ error: 'rawPayload required for test' }), { status: 400 });
      }

      const events = normalizeWithConfig(rawPayload, adapterConfig as AdapterConfig);
      const matrix = aggregateToMatrix(events, Math.floor(Date.now() / 1000));

      return new Response(
        JSON.stringify({ events, matrix }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (action === 'commit') {
      if (!adapterConfig) {
        return new Response(JSON.stringify({ error: 'adapterConfig required for commit' }), { status: 400 });
      }
      const vErr = validateAdapterConfig(adapterConfig);
      if (vErr) {
        return new Response(JSON.stringify({ error: vErr }), { status: 400 });
      }
      await env.VM_TENANT_DIRECTORY.put(`adapter:${tenantId}`, JSON.stringify(adapterConfig));
      return new Response(
        JSON.stringify({ committed: true, tenantId }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(JSON.stringify({ error: `Unknown action: ${action}` }), { status: 400 });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500 }
    );
  }
};