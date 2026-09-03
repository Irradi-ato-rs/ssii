// src/pages/api/governance/onboard.ts
// Governance/admin exclusive: tenant registration, key rotation, listing.
import type { APIContext } from 'astro';
import type { EngineParams } from '../../../lib/scoring-engine';

export const prerender = false;

export const POST: APIContext['POST'] = async ({ request, locals, env }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
  if (locals.user.role !== 'governance' && locals.user.role !== 'admin') {
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 });
  }

  try {
    const { action, tenantId, idpConfig, userRoles, initialParams } = await request.json();

    switch (action) {
      case 'register': {
        if (!tenantId || !idpConfig) {
          return new Response(JSON.stringify({ error: 'Missing tenantId or idpConfig' }), { status: 400 });
        }

        // Write IdP config to KV
        await env.VM_TENANT_DIRECTORY.put(`idp:${tenantId}`, JSON.stringify(idpConfig));

        // Generate API key
        const randomBytes = new Uint8Array(32);
        crypto.getRandomValues(randomBytes);
        const apiKey = Array.from(randomBytes).map((b: number) => b.toString(16).padStart(2, '0')).join('');
        await env.VM_TENANT_DIRECTORY.put(`apikey:${tenantId}`, apiKey);

        // Set initial hyperparams if provided (supports multi-block)
        if (initialParams) {
          await env.VM_TENANT_DIRECTORY.put(`hyperparams:${tenantId}`, JSON.stringify(initialParams));
        }

        // Write user roles to allowlist KV (merged)
        if (userRoles && Object.keys(userRoles).length > 0) {
          const existingRaw = await env.VM_TENANT_DIRECTORY.get('role_allowlist');
          let allowlist: Record<string, string[]> = {};
          if (existingRaw) {
            try { allowlist = JSON.parse(existingRaw); } catch (_) {}
          }
          for (const [email, role] of Object.entries(userRoles)) {
            const r = role as string;
            if (!allowlist[r]) allowlist[r] = [];
            if (!allowlist[r].includes(email)) allowlist[r].push(email);
          }
          await env.VM_TENANT_DIRECTORY.put('role_allowlist', JSON.stringify(allowlist));
        }

        // Append to tenant registry
        const regRaw = await env.VM_TENANT_DIRECTORY.get('tenant_registry');
        let registry: string[] = [];
        if (regRaw) {
          try { registry = JSON.parse(regRaw); } catch (_) {}
        }
        if (!registry.includes(tenantId)) registry.push(tenantId);
        await env.VM_TENANT_DIRECTORY.put('tenant_registry', JSON.stringify(registry));

        return new Response(JSON.stringify({
          status: 'registered',
          tenantId,
          apiKey,
          webhookUrl: `https://void.fzoirm.com/ingest/${tenantId}`,
          hyperparams: initialParams ? 'custom' : 'default',
          blockCount: initialParams?.blockCount || 1,
          rolesAssigned: userRoles ? Object.keys(userRoles).length : 0,
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      case 'list': {
        const registryRaw = await env.VM_TENANT_DIRECTORY.get('tenant_registry');
        const registry = registryRaw ? JSON.parse(registryRaw) : [];
        return new Response(JSON.stringify({ tenants: registry }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      case 'revoke': {
        if (!tenantId) {
          return new Response(JSON.stringify({ error: 'Missing tenantId' }), { status: 400 });
        }
        const randomBytes = new Uint8Array(32);
        crypto.getRandomValues(randomBytes);
        const newKey = Array.from(randomBytes).map((b: number) => b.toString(16).padStart(2, '0')).join('');
        await env.VM_TENANT_DIRECTORY.put(`apikey:${tenantId}`, newKey);
        return new Response(JSON.stringify({
          status: 'key_rotated',
          tenantId,
          newApiKey: newKey,
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      default:
        return new Response(JSON.stringify({ error: 'Unknown action' }), { status: 400 });
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), { status: 500 });
  }
};