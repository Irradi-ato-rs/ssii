// src/pages/api/sandbox.ts
import type { APIContext } from 'astro';
import { runScoringEngine, type PaddedStreamNode } from '../../lib/scoring-engine';

export const prerender = false;

export const POST: APIContext['POST'] = async ({ request, locals }) => {
  if (!locals.user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  try {
    const { paddedStream, threatIntelVector, previousStream, previousThreatIntelVector } = await request.json();

    if (!Array.isArray(paddedStream) || paddedStream.length !== 12) {
      return new Response(JSON.stringify({ error: 'Expected 12-node paddedStream' }), { status: 400 });
    }

    const result = runScoringEngine(
      paddedStream as PaddedStreamNode[],
      threatIntelVector || [0, 0, 0],
      previousStream as PaddedStreamNode[] | undefined,
      previousThreatIntelVector || undefined
    );

    const isTech = locals.user.role === 'engineer' || locals.user.role === 'admin';
    const response: Record<string, unknown> = {
      metric_a_compliance: result.metric_a_compliance,
      metric_a_velocity: result.metric_a_velocity,
      metric_b_integrity: result.metric_b_integrity,
      status: result.status,
      watermelon_index: result.watermelon_index,
      honest_failure_index: result.honest_failure_index,
      provenance: 'sandbox',
    };
    if (isTech) {
      response.row_validations = result.row_validations;
      response.spectral_analysis = result.spectral_analysis;
    }

    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500 }
    );
  }
};   