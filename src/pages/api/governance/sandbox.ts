// src/pages/api/governance/sandbox.ts
// Governance/admin exclusive: test candidate hyperparams against a tenant's
// real telemetry snapshot before committing to KV.
import type { APIContext } from 'astro';
import { runScoringEngine, type PaddedStreamNode, type EngineParams } from '../../../lib/scoring-engine';

export const prerender = false;

const WRITABLE_FIELDS = new Set([
  'blockCount', 'priorityAlpha', 'baseEnablerWeights',
  'decayRate', 'driftVolatility', 'sigmoidSteepness',
  'sigmoidMidpoint', 'chaosScale', 'statusThreshold',
  'breakerThreshold', 'breakerFloor',
]);

function validateCandidateParams(p: any): string | null {
  if (typeof p !== 'object' || p === null) return 'candidateParams must be an object';

  for (const key of Object.keys(p)) {
    if (!WRITABLE_FIELDS.has(key)) {
      return `Field '${key}' is not writable. Allowed: ${[...WRITABLE_FIELDS].join(', ')}`;
    }
  }

  if (p.breakerThreshold !== undefined) {
    if (typeof p.breakerThreshold !== 'number' || p.breakerThreshold < 0.01 || p.breakerThreshold > 0.2)
      return 'breakerThreshold must be in [0.01, 0.2]';
  }
  if (p.statusThreshold !== undefined) {
    if (typeof p.statusThreshold !== 'number' || p.statusThreshold < 0.1 || p.statusThreshold > 0.5)
      return 'statusThreshold must be in [0.1, 0.5]';
  }
  if (p.breakerThreshold !== undefined && p.statusThreshold !== undefined) {
    if (p.breakerThreshold >= p.statusThreshold)
      return 'breakerThreshold must be < statusThreshold (breaker must fire before status flips)';
  }
  if (p.priorityAlpha !== undefined) {
    if (!Array.isArray(p.priorityAlpha) || p.priorityAlpha.length !== 4)
      return 'priorityAlpha must be an array of 4 values';
    const sum = p.priorityAlpha.reduce((a: number, b: number) => a + b, 0);
    if (Math.abs(sum - 1.0) > 0.01)
      return `priorityAlpha must sum to 1.0 (got ${sum.toFixed(4)})`;
  }
  if (p.baseEnablerWeights !== undefined) {
    if (!Array.isArray(p.baseEnablerWeights) || p.baseEnablerWeights.length !== 3)
      return 'baseEnablerWeights must be an array of 3 values';
  }
  if (p.blockCount !== undefined) {
    if (!Number.isInteger(p.blockCount) || p.blockCount < 1 || p.blockCount > 720)
      return 'blockCount must be an integer in [1, 720]';
  }

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
    const { tenantId, candidateParams, action } = await request.json();

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

    // Read current hyperparams from KV (3-tier: tenant → global → null)
    let currentParams: any = null;
    try {
      const tenantRaw = await env.VM_TENANT_DIRECTORY.get(`hyperparams:${tenantId}`);
      if (tenantRaw) currentParams = JSON.parse(tenantRaw);
    } catch (_) {}
    if (!currentParams) {
      try {
        const globalRaw = await env.VM_TENANT_DIRECTORY.get('hyperparams:global');
        if (globalRaw) currentParams = JSON.parse(globalRaw);
      } catch (_) {}
    }

    // Read tenant's last telemetry snapshot
    let snapshot = null;
    try {
      const stored = await env.VM_TENANT_DIRECTORY.get(`telemetry:${tenantId}`);
      if (stored) snapshot = JSON.parse(stored);
    } catch (_) {}

    if (!snapshot || !snapshot.current) {
      return new Response(JSON.stringify({ error: 'No telemetry snapshot for this tenant' }), { status: 404 });
    }

    const { paddedStream, threatIntelVector } = snapshot.current;
    const previous = snapshot.previous || null;

    // Run with current params (baseline)
    const baseline = runScoringEngine(
      paddedStream as PaddedStreamNode[] | PaddedStreamNode[][],
      threatIntelVector || [0, 0, 0],
      previous ? previous.paddedStream : undefined,
      previous ? previous.threatIntelVector : undefined,
      currentParams || undefined
    );

    // Run with candidate params (test)
    let test = null;
    if (candidateParams) {
      const vErr = validateCandidateParams(candidateParams);
      if (vErr) {
        return new Response(JSON.stringify({ error: vErr }), { status: 400 });
      }
      test = runScoringEngine(
        paddedStream as PaddedStreamNode[] | PaddedStreamNode[][],
        threatIntelVector || [0, 0, 0],
        previous ? previous.paddedStream : undefined,
        previous ? previous.threatIntelVector : undefined,
        candidateParams as Partial<EngineParams>
      );
    }

    // If action is "commit", validate then write to KV
    if (action === 'commit' && candidateParams) {
      const vErr = validateCandidateParams(candidateParams);
      if (vErr) {
        return new Response(JSON.stringify({ error: vErr }), { status: 400 });
      }

      const previousRaw = await env.VM_TENANT_DIRECTORY.get(`hyperparams:${tenantId}`);
      await env.VM_TENANT_DIRECTORY.put(`hyperparams:${tenantId}`, JSON.stringify(candidateParams));

      console.log(`[GOV-AUDIT] hyperparams commit`, {
        tenantId,
        actor: locals.user.email,
        role: locals.user.role,
        previous: previousRaw ? JSON.parse(previousRaw) : null,
        committed: candidateParams,
        timestamp: new Date().toISOString(),
      });
    }

    return new Response(JSON.stringify({
      tenantId,
      currentParams: currentParams || 'defaults',
      candidateParams: candidateParams || null,
      baseline,
      test,
      committed: action === 'commit' ? true : false,
      snapshotTimestamp: snapshot.current.timestamp,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.error(`[GOV-SANDBOX] Internal error:`, err);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500 }
    );
  }
};   