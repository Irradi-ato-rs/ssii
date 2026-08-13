// src/pages/api/compute.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { runScoringEngine, type PaddedStreamNode } from '../../lib/scoring-engine';

async function verifyIngestionSignature(rawBody: string, signatureHeader: string | null): Promise<boolean> {
  if (!signatureHeader || !env.INGESTION_SERVICE_SECRET) return false;
  return signatureHeader === env.INGESTION_SERVICE_SECRET;
}

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const rawBody = await request.text();
    const signatureHeader = request.headers.get('X-VoidMetric-Ingestion-Signature');
    const isVerifiedIngestion = await verifyIngestionSignature(rawBody, signatureHeader);

    if (!isVerifiedIngestion && !locals.user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    const body = JSON.parse(rawBody);
    const paddedStream = body.paddedStream as PaddedStreamNode[];
    const tenantId = body.tenantId; // Critical: Must be sent from void

    if (!paddedStream || !Array.isArray(paddedStream) || paddedStream.length !== 32) {
      return new Response(JSON.stringify({ error: 'Invalid stream' }), { status: 400 });
    }

    const result = runScoringEngine(paddedStream, body.threatIntelVector || [0.0, 0.0, 0.0]);

    // CRITICAL: Write to KV for Dashboard
    if (env.VM_LIVE_POSTURE_CACHE && isVerifiedIngestion && tenantId) {
      try {
        await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify({
          metric_a_compliance: result.metric_a_compliance,
          metric_b_integrity: result.metric_b_integrity,
          status: result.status,
          theater_gap_delta: result.theater_gap_delta,
          computedAt: new Date().toISOString()
        }));
        console.log(`[SSII] ✅ Cached data for tenant: ${tenantId}`);
      } catch (err) {
        console.error(`[SSII] ❌ KV Write Failed: ${err}`);
      }
    }

    return new Response(JSON.stringify({
      metric_a_compliance: result.metric_a_compliance,
      metric_b_integrity: result.metric_b_integrity,
      status: result.status,
      provenance: isVerifiedIngestion ? "verified_ingestion" : "sandbox"
    }), { status: 200, headers: { "Content-Type": "application/json" } });

  } catch (error) {
    console.error("Compute Error:", error);
    return new Response(JSON.stringify({ error: "Failed" }), { status: 400 });
  }
};   