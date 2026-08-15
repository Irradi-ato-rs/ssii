// workers/ssii-consumer.ts
// MOVING src/pages/api/compute.ts
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
    for (const message of batch.messages) {
      try {
        const { tenantId, paddedStream, threatIntelVector } = message.body;

        // 1. Run Scoring Engine (Pure Compute)
        const result = runScoringEngine(paddedStream, threatIntelVector);

        // 2. Write to KV (Sovereign State)
        if (env.VM_LIVE_POSTURE_CACHE && tenantId) {
          const cacheData = {
            metric_a_compliance: result.metric_a_compliance,
            metric_b_integrity: result.metric_b_integrity,
            status: result.status,
            theater_gap_delta: result.theater_gap_delta,
            spectral_analysis: result.spectral_analysis,
            computedAt: new Date().toISOString()
          };
          
          await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify(cacheData));
          console.log(`[SSII] ✅ Cached: ${tenantId} | Score B: ${result.metric_b_integrity}`);
        }

        message.ack(); // Success
      } catch (err) {
        console.error(`[SSII] ❌ Error for ${message.body.tenantId}: ${err.message}`);
        message.retry(); // Auto-retry
      }
    }
  }
};   