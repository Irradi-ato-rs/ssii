// src/pages/api/governance/notify.ts
// Governance/admin exclusive: configure and test notification targets
// for the dispatch pipeline. Writes to KV key `notify:${tenantId}`.
import type { APIContext } from 'astro';

export const prerender = false;

interface NotifyConfig {
  pagerduty_routing_key?: string;
  slack_webhook_url?: string;
  cooldown_seconds?: number;
  escalate_after?: number;
}

function validateNotifyConfig(cfg: any): string | null {
  if (typeof cfg !== 'object' || cfg === null) return 'Config must be an object';

  const ALLOWED = new Set(['pagerduty_routing_key', 'slack_webhook_url', 'cooldown_seconds', 'escalate_after']);
  for (const key of Object.keys(cfg)) {
    if (!ALLOWED.has(key)) return `Field '${key}' is not writable. Allowed: ${[...ALLOWED].join(', ')}`;
  }

  if (cfg.pagerduty_routing_key !== undefined) {
    if (typeof cfg.pagerduty_routing_key !== 'string' || cfg.pagerduty_routing_key.length < 10)
      return 'pagerduty_routing_key must be a non-empty string (min 10 chars)';
  }
  if (cfg.slack_webhook_url !== undefined) {
    if (typeof cfg.slack_webhook_url !== 'string' || !cfg.slack_webhook_url.startsWith('https://'))
      return 'slack_webhook_url must be a valid https:// URL';
  }
  if (cfg.cooldown_seconds !== undefined) {
    if (!Number.isInteger(cfg.cooldown_seconds) || cfg.cooldown_seconds < 60 || cfg.cooldown_seconds > 86400)
      return 'cooldown_seconds must be an integer in [60, 86400]';
  }
  if (cfg.escalate_after !== undefined) {
    if (!Number.isInteger(cfg.escalate_after) || cfg.escalate_after < 2 || cfg.escalate_after > 24)
      return 'escalate_after must be an integer in [2, 24]';
  }

  if (!cfg.pagerduty_routing_key && !cfg.slack_webhook_url)
    return 'At least one notification target (PagerDuty or Slack) is required';

  return null;
}

export const POST: APIContext['POST'] = async ({ request, locals, env }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
  if (locals.user.role !== 'governance' && locals.user.role !== 'admin') {
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 });
  }

  try {
    const { tenantId, action, notifyConfig } = await request.json();

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
      const raw = await env.VM_TENANT_DIRECTORY.get(`notify:${tenantId}`);
      return new Response(
        JSON.stringify({ notifyConfig: raw ? JSON.parse(raw) : null }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (action === 'test') {
      if (!notifyConfig) {
        return new Response(JSON.stringify({ error: 'notifyConfig required for test' }), { status: 400 });
      }
      const vErr = validateNotifyConfig(notifyConfig);
      if (vErr) {
        return new Response(JSON.stringify({ error: vErr }), { status: 400 });
      }

      const results: Record<string, { ok: boolean; detail: string }> = {};

      // Test PagerDuty
      if (notifyConfig.pagerduty_routing_key) {
        try {
          const res = await fetch('https://events.pagerduty.com/v2/enqueue', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              routing_key: notifyConfig.pagerduty_routing_key,
              event_action: 'trigger',
              payload: {
                summary: `[TEST] VoidMetric notification check for ${tenantId}`,
                severity: 'info',
                source: 'voidmetric',
                component: 'governance-console',
                group: tenantId,
                details: {
                  message: 'This is a test alert from the VoidMetric governance console. No action required.',
                  timestamp: new Date().toISOString(),
                },
              },
            }),
            signal: AbortSignal.timeout(10_000),
          });
          const body = await res.json();
          results.pagerduty = {
            ok: res.ok,
            detail: res.ok ? `Event ID: ${body.status || body.incident_key || 'accepted'}` : `HTTP ${res.status}: ${body.message || 'error'}`,
          };
        } catch (err) {
          results.pagerduty = { ok: false, detail: (err as Error).message };
        }
      }

      // Test Slack
      if (notifyConfig.slack_webhook_url) {
        try {
          const res = await fetch(notifyConfig.slack_webhook_url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              text: `✅ **VoidMetric Test Alert**\nTenant: ${tenantId}\nThis is a test from the governance console. No action required.`,
            }),
            signal: AbortSignal.timeout(10_000),
          });
          results.slack = {
            ok: res.ok,
            detail: res.ok ? 'Message delivered' : `HTTP ${res.status}: ${await res.text()}`,
          };
        } catch (err) {
          results.slack = { ok: false, detail: (err as Error).message };
        }
      }

      return new Response(
        JSON.stringify({ results }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (action === 'commit') {
      if (!notifyConfig) {
        return new Response(JSON.stringify({ error: 'notifyConfig required for commit' }), { status: 400 });
      }
      const vErr = validateNotifyConfig(notifyConfig);
      if (vErr) {
        return new Response(JSON.stringify({ error: vErr }), { status: 400 });
      }

      const previousRaw = await env.VM_TENANT_DIRECTORY.get(`notify:${tenantId}`);
      await env.VM_TENANT_DIRECTORY.put(`notify:${tenantId}`, JSON.stringify(notifyConfig));

      console.log(`[GOV-AUDIT] notify commit`, {
        tenantId,
        actor: locals.user.email,
        role: locals.user.role,
        previous: previousRaw ? JSON.parse(previousRaw) : null,
        committed: notifyConfig,
        timestamp: new Date().toISOString(),
      });

      return new Response(
        JSON.stringify({ committed: true, tenantId }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(JSON.stringify({ error: `Unknown action: ${action}` }), { status: 400 });
  } catch (err) {
    console.error(`[GOV-NOTIFY] Internal error:`, err);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500 }
    );
  }
};   