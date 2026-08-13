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

    // Allow authenticated dashboard users OR signed internal void worker
    if (!isVerifiedIngestion && !locals.user) {
      return new Response(JSON.stringify({ error: 'Unauthorized payload transmission rejection.' }), { status: 401 });
    }

    const body = JSON.parse(rawBody);
    const paddedStream = body.paddedStream as PaddedStreamNode[];
    const threatIntel = body.threatIntelVector || [0.0, 0.0, 0.0];
    const tenantId = body.tenantId; // Ensure void sends this

    if (!paddedStream || !Array.isArray(paddedStream) || paddedStream.length !== 32) {
      return new Response(JSON.stringify({ error: 'Invalid payload matrix. Expected a padded 32-element array stream.' }), { status: 400 });
    }

    const result = runScoringEngine(paddedStream, threatIntel);

    const userRole = (locals.user as any)?.role;
    const includeDetail = isVerifiedIngestion || userRole === 'engineer' || userRole === 'admin';

    const responsePayload: any = {
      metric_a_compliance: result.metric_a_compliance,
      metric_b_integrity: result.metric_b_integrity,
      status: result.status,
      theater_gap_delta: result.theater_gap_delta,
      provenance: isVerifiedIngestion ? "verified_ingestion" : "user_submitted_sandbox",
    };

    if (includeDetail) {
      responsePayload.row_validations = result.row_validations;
      responsePayload.spectral_analysis = result.spectral_analysis;
    }

    // CRITICAL FIX: Save to KV for Dashboard Visualization
    // This runs for verified ingestion (void worker) regardless of user session
    if (env.VM_LIVE_POSTURE_CACHE && isVerifiedIngestion && tenantId) {
      try {
        const cacheData = {
          metric_a_compliance: result.metric_a_compliance,
          metric_b_integrity: result.metric_b_integrity,
          status: result.status,
          theater_gap_delta: result.theater_gap_delta,
          computedAt: new Date().toISOString(),
          source: "void_worker"
        };
        await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify(cacheData));
        console.log(`[SSII] Cached posture for tenant: ${tenantId}`);
      } catch (cacheErr) {
        console.error('[SSII] Failed to cache posture:', cacheErr);
      }
    }

    return new Response(
      JSON.stringify(responsePayload),
      { status: 200, headers: { "Content-Type": "application/json", "X-VoidMetric-Engine": "v3.1-Provenance-Aware" } }
    );

  } catch (error) {
    console.error("Compute Execution Pipeline Failure:", error);
    return new Response(JSON.stringify({ error: "Malformed streaming metric payload." }), { status: 400 });
  }
};   