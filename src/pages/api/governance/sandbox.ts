// src/pages/api/governance/sandbox.ts
// Governance/admin exclusive: test candidate hyperparams against a tenant's
// real telemetry snapshot before committing to KV.
import type { APIContext } from 'astro';
import { runScoringEngine, type PaddedStreamNode, type EngineParams } from '../../../lib/scoring-engine';

export const prerender = false;

export const POST: APIContext['POST'] = async ({ request, locals, env }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }
  if (locals.user.role !== 'governance' && locals.user.role !== 'admin') {
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 });
  }

  try {
    const { tenantId, candidateParams, action } = await request.json();

    if (!tenantId) {
      return new Response(JSON.stringify({ error: 'Missing tenantId' }), { status: 400 });
    }

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
    const test = candidateParams
      ? runScoringEngine(
          paddedStream as PaddedStreamNode[] | PaddedStreamNode[][],
          threatIntelVector || [0, 0, 0],
          previous ? previous.paddedStream : undefined,
          previous ? previous.threatIntelVector : undefined,
          candidateParams as Partial<EngineParams>
        )
      : null;

    // If action is "commit", write to KV
    if (action === 'commit' && candidateParams) {
      await env.VM_TENANT_DIRECTORY.put(`hyperparams:${tenantId}`, JSON.stringify(candidateParams));
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
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500 }
    );
  }
};