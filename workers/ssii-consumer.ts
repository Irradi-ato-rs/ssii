// workers/ssii-consumer.ts
// ORIGINALLY src/pages/api/compute.ts
import { runScoringEngine, type PaddedStreamNode } from '../src/lib/scoring-engine';

export interface Env {
  VM_LIVE_POSTURE_CACHE: KVNamespace;
}

export interface VoidMessage {
  type: 'signal_update';
  tenantId: string;
  paddedStream: PaddedStreamNode[];
  threatIntelVector: number[];
  timestamp: number;
}

export default {
  async queue(batch: MessageBatch<VoidMessage>, env: Env): Promise<void> {
    console.log(`[SSII] Received batch of ${batch.messages.length} messages`);
    
    for (const message of batch.messages) {
      try {
        const body = message.body;
        
        // 1. VALIDATION GUARD: Prevents crash on malformed manual test messages
        if (!body.paddedStream || !Array.isArray(body.paddedStream)) {
          console.warn(`[SSII] ⚠️ Invalid message format. Missing paddedStream. Acking to skip.`, body);
          message.ack(); // Skip bad messages to prevent infinite retry loops
          continue;
        }

        const { tenantId, paddedStream, threatIntelVector } = body;
        
        // 2. Execute Scoring Engine
        const result = runScoringEngine(paddedStream, threatIntelVector || [0, 0, 0]);

        // 3. Update KV Cache
        if (env.VM_LIVE_POSTURE_CACHE && tenantId) {
          await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify({
            metric_a_compliance: result.metric_a_compliance,
            metric_b_integrity: result.metric_b_integrity,
            status: result.status,
            theater_gap_delta: result.theater_gap_delta,
            spectral_analysis: result.spectral_analysis,
            computedAt: new Date().toISOString()
          }));
          console.log(`[SSII] ✅ Cached: ${tenantId}`);
        }
        
        message.ack();
      } catch (err) {
        console.error(`[SSII] ❌ Critical Error: ${err.message}`, message.body);
        // Retry only valid messages that failed due to transient errors
        message.retry(); 
      }
    }
  },
  // CRITICAL: Prevents "Invalid URL" on HTTP health checks
  async fetch(): Promise<Response> {
    return new Response("SSII Consumer Active", { status: 200 });
  }
};   