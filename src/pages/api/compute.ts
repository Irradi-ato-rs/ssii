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
    
    // DEBUG: Log verification status
    console.log(`[SSII] Received POST. Signature Present: ${!!signatureHeader}`);
    console.log(`[SSII] Secret Loaded: ${!!env.INGESTION_SERVICE_SECRET}`);
    
    const isVerifiedIngestion = await verifyIngestionSignature(rawBody, signatureHeader);
    console.log(`[SSII] Verification Match: ${isVerifiedIngestion}`);

    if (!isVerifiedIngestion && !locals.user) {
      console.warn(`[SSII] Rejected: Not verified and no user session.`);
      return new Response(JSON.stringify({ error: 'Unauthorized payload transmission rejection.' }), { status: 401 });
    }

    const body = JSON.parse(rawBody);
    const paddedStream = body.paddedStream as PaddedStreamNode[];
    const tenantId = body.tenantId; 

    if (!paddedStream || !Array.isArray(paddedStream) || paddedStream.length !== 32) {
      return new Response(JSON.stringify({ error: 'Invalid stream' }), { status: 400 });
    }

    const result = runScoringEngine(paddedStream, body.threatIntelVector || [0.0, 0.0, 0.0]);

    // CRITICAL: Block and Write to KV
    if (env.VM_LIVE_POSTURE_CACHE && isVerifiedIngestion && tenantId) {
      try {
        const cacheData = {
          metric_a_compliance: result.metric_a_compliance,
          metric_b_integrity: result.metric_b_integrity,
          status: result.status,
          theater_gap_delta: result.theater_gap_delta,
          computedAt: new Date().toISOString()
        };
        
        await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify(cacheData));
        console.log(`[SSII] ✅ CACHED DATA FOR TENANT: ${tenantId}`);
      } catch (cacheErr) {
        console.error(`[SSII] ❌ KV WRITE ERROR: ${cacheErr}`);
      }
    } else {
      console.warn(`[SSII] Skipped Cache. Verified: ${isVerifiedIngestion}, Tenant: ${tenantId}, CacheBound: ${!!env.VM_LIVE_POSTURE_CACHE}`);
    }

    return new Response(JSON.stringify({
      metric_a_compliance: result.metric_a_compliance,
      metric_b_integrity: result.metric_b_integrity,
      status: result.status,
      provenance: isVerifiedIngestion ? "verified_ingestion" : "sandbox"
    }), { status: 200, headers: { "Content-Type": "application/json" } });

  } catch (error) {
    console.error("Compute Critical Error:", error);
    return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500 });
  }
};