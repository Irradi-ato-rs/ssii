// workers/dispatcher.ts
// Consumes posture_change events from ssii-consumer.
// Reads posture cache for context (consecutive CRITICAL count).
// Routes to notification targets based on the dispatch vector.
//
// Bindings:
//   VM_LIVE_POSTURE_CACHE — KV (shared with ssii-consumer)
//   VM_TENANT_DIRECTORY   — KV (for tenant config: notification targets)
//   VM_DISPATCH_STATE     — KV (per-tenant dispatch state: consecutive counts, cooldowns)

import type { ScoringResult } from '../src/lib/scoring-engine';

interface DispatchMessage {
  type: 'posture_change';
  tenantId: string;
  result: ScoringResult;
  timestamp: number;
}

interface TenantNotificationConfig {
  pagerduty_routing_key?: string;
  slack_webhook_url?: string;
  email?: string;
  cooldown_seconds?: number;
  escalate_after?: number;
}

interface DispatchState {
  consecutive_critical: number;
  last_dispatch_ts: number;
  last_status: string;
}

interface Env {
  VM_LIVE_POSTURE_CACHE: KVNamespace;
  VM_TENANT_DIRECTORY: KVNamespace;
  VM_DISPATCH_STATE: KVNamespace;
}

const DEFAULT_COOLDOWN = 3600;
const DEFAULT_ESCALATE_AFTER = 3;
const FETCH_TIMEOUT_MS = 10_000;

export default {
  async queue(batch: MessageBatch<DispatchMessage>, env: Env): Promise<void> {
    console.log(`[DISPATCH] Received batch of ${batch.messages.length} messages`);

    for (const message of batch.messages) {
      try {
        const { tenantId, result, timestamp } = message.body;

        // 1. Load tenant notification config
        const configRaw = await env.VM_TENANT_DIRECTORY.get(`notify:${tenantId}`);
        const config: TenantNotificationConfig = configRaw ? JSON.parse(configRaw) : {};
        const cooldown = config.cooldown_seconds ?? DEFAULT_COOLDOWN;
        const escalateAfter = config.escalate_after ?? DEFAULT_ESCALATE_AFTER;

        // 2. Load dispatch state (resilient to corruption)
        let state: DispatchState = { consecutive_critical: 0, last_dispatch_ts: 0, last_status: 'NOMINAL' };
        const stateRaw = await env.VM_DISPATCH_STATE.get(`state:${tenantId}`);
        if (stateRaw) {
          try {
            const parsed = JSON.parse(stateRaw);
            if (typeof parsed.consecutive_critical === 'number' &&
                typeof parsed.last_dispatch_ts === 'number' &&
                typeof parsed.last_status === 'string') {
              state = parsed;
            } else {
              console.warn(`[DISPATCH] ${tenantId}: state schema mismatch, resetting`);
            }
          } catch {
            console.warn(`[DISPATCH] ${tenantId}: state JSON parse failed, resetting`);
          }
        }

        // 3. Update consecutive counter
        if (result.status === 'CRITICAL_RISK_SWITCH_TRIGGERED') {
          state.consecutive_critical++;
        } else {
          state.consecutive_critical = 0;
        }

        // 4. Determine dispatch action
        const action = determineAction(result, state, cooldown, escalateAfter, timestamp);

        // 5. Execute dispatch
        if (action !== 'none') {
          await executeDispatch(action, result, state, config, tenantId);
          state.last_dispatch_ts = timestamp;
        }
        state.last_status = result.status; // always track current status

        // 6. Persist state (TTL 7d — clears stale state for inactive tenants)
        await env.VM_DISPATCH_STATE.put(
          `state:${tenantId}`,
          JSON.stringify(state),
          { expirationTtl: 7 * 86400 }
        );

        console.log(`[DISPATCH] ${tenantId}: action=${action} status=${result.status} consecutive=${state.consecutive_critical}`);
        message.ack();
      } catch (err) {
        console.error(`[DISPATCH] ❌ Error: ${(err as Error).message}`, message.body);
        if (message.attempts > 5) {
          console.error(`[DISPATCH] Poison message after ${message.attempts} attempts. Acking to skip.`);
          message.ack();
        } else {
          message.retry();
        }
      }
    }
  },

  async fetch(): Promise<Response> {
    return new Response("Dispatcher Active", { status: 200 });
  },
};

// ─── Action Determination ─────────────────────────────────────────────────────

function determineAction(
  result: ScoringResult,
  state: DispatchState,
  cooldown: number,
  escalateAfter: number,
  now: number
): 'page_critical' | 'page_escalated' | 'notify_watermelon' | 'notify_resonance' | 'none' {
  const inCooldown = (now - state.last_dispatch_ts) < cooldown;

  // Escalation: N consecutive CRITICAL → page regardless of cooldown
  if (result.status === 'CRITICAL_RISK_SWITCH_TRIGGERED' && state.consecutive_critical >= escalateAfter) {
    return 'page_escalated';
  }

  // Critical (first occurrence or within cooldown but not escalated)
  if (result.status === 'CRITICAL_RISK_SWITCH_TRIGGERED') {
    if (inCooldown && state.last_status === 'CRITICAL_RISK_SWITCH_TRIGGERED') return 'none';
    return 'page_critical';
  }

  // Watermelon: compliance masking failure
  if (result.watermelonIndex > 0.5) {
    if (inCooldown) return 'none';
    return 'notify_watermelon';
  }

  // Resonance: probable exploit chain
  if (result.spectralAnalysis.resonanceExploitChainDetected) {
    if (inCooldown) return 'none';
    return 'notify_resonance';
  }

  return 'none';
}

// ─── Dispatch Execution ───────────────────────────────────────────────────────

async function executeDispatch(
  action: string,
  result: ScoringResult,
  state: DispatchState,
  config: TenantNotificationConfig,
  tenantId: string
): Promise<void> {
  const summary = buildSummary(result, state, tenantId);

  // PagerDuty
  if ((action === 'page_critical' || action === 'page_escalated') && config.pagerduty_routing_key) {
    const severity = action === 'page_escalated' ? 'critical' : 'error';
    const description = action === 'page_escalated'
      ? `[ESCALATED] ${tenantId}: ${state.consecutive_critical} consecutive CRITICAL cycles`
      : `[CRITICAL] ${tenantId}: Risk Switch triggered`;

    try {
      const res = await fetch(`https://events.pagerduty.com/v2/enqueue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          routing_key: config.pagerduty_routing_key,
          event_action: 'trigger',
          payload: {
            summary: description,
            severity,
            source: 'voidmetric',
            component: 'integrity-portal',
            group: tenantId,
            details: summary,
          },
        }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) {
        console.warn(`[DISPATCH] PagerDuty ${res.status}: ${await res.text()}`);
      }
    } catch (e) {
      console.warn(`[DISPATCH] PagerDuty failed: ${(e as Error).message}`);
    }
  }

  // Slack
  if (config.slack_webhook_url) {
    const emoji = action === 'page_escalated' ? '🚨' : action === 'page_critical' ? '🔴' : action === 'notify_watermelon' ? '🍉' : '⚠️';

    try {
      const res = await fetch(config.slack_webhook_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `${emoji} **VoidMetric // ${tenantId}**\n${summary}`,
        }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) {
        console.warn(`[DISPATCH] Slack ${res.status}: ${await res.text()}`);
      }
    } catch (e) {
      console.warn(`[DISPATCH] Slack failed: ${(e as Error).message}`);
    }
  }
}

// ─── Summary Builder ──────────────────────────────────────────────────────────

function buildSummary(result: ScoringResult, state: DispatchState, tenantId: string): string {
  const lines: string[] = [
    `Tenant: ${tenantId}`,
    `Status: ${result.status.replace(/_/g, ' ')}`,
    `Metric A (Compliance): ${(result.metricACompliance * 100).toFixed(1)}%`,
    `Metric B (Integrity): ${(result.metricBIntegrity * 100).toFixed(1)}%`,
    `Velocity: ${result.metricAVelocity !== null ? (result.metricAVelocity > 0 ? '+' : '') + (result.metricAVelocity * 100).toFixed(2) : 'n/a'}`,
    `Watermelon Index: ${(result.watermelonIndex * 100).toFixed(1)}%`,
    `Honest Failure: ${(result.honestFailureIndex * 100).toFixed(1)}%`,
    `Chaos Penalty: ${result.spectralAnalysis.chaosIndexPenalty}`,
    `Resonance: ${result.spectralAnalysis.resonanceExploitChainDetected ? 'DETECTED' : 'none'}`,
  ];

  if (result.temporal) {
    lines.push(`Blocks: ${result.temporal.blockCount}`);
    lines.push(`Onset: block ${result.temporal.onsetBlock === -1 ? 'none' : result.temporal.onsetBlock}`);
    lines.push(`Persistence: ${result.temporal.persistence} consecutive block(s)`);
    lines.push(`Trend: ${result.temporal.trend}`);
    if (result.temporal.breakerBlocks.length > 0) {
      lines.push(`Breaker trips: blocks [${result.temporal.breakerBlocks.join(', ')}]`);
    }
  }

  lines.push(`Consecutive CRITICAL: ${state.consecutive_critical}`);
  return lines.join('\n');
}   