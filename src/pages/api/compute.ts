// src/pages/api/compute.ts
export const prerender = false;
import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { runScoringEngine, type PaddedStreamNode } from '../../lib/scoring-engine';

async function verifyIngestionSignature(rawBody: string, signatureHeader: string | null): Promise<boolean> {
  if (!signatureHeader || !env.INGESTION_SERVICE_SECRET) return false;
  // Direct comparison is fine here — Service Bindings already guarantee
  // this header can only meaningfully arrive from ingestion-core; this
  // check exists only to distinguish intent within this Worker, not to
  // resist network-level forgery.
  return signatureHeader === env.INGESTION_SERVICE_SECRET;
}

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const rawBody = await request.text();
    const signatureHeader = request.headers.get('X-VoidMetric-Ingestion-Signature');
    const isVerifiedIngestion = await verifyIngestionSignature(rawBody, signatureHeader);

    if (!isVerifiedIngestion && !locals.user) {
      return new Response(JSON.stringify({ error: 'Unauthorized payload transmission rejection.' }), { status: 401 });
    }

    const body = JSON.parse(rawBody);
    const paddedStream = body.paddedStream as PaddedStreamNode[];
    const threatIntel = body.threatIntelVector || [0.0, 0.0, 0.0];

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

    return new Response(
      JSON.stringify(responsePayload),
      { status: 200, headers: { "Content-Type": "application/json", "X-VoidMetric-Engine": "v3.1-Provenance-Aware" } }
    );

  } catch (error) {
    console.error("Compute Execution Pipeline Failure:", error);
    return new Response(JSON.stringify({ error: "Malformed streaming metric payload." }), { status: 400 });
  }
};