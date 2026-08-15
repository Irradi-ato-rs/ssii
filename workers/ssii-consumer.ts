// /workers/ssii-consumer.ts
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

// CRITICAL: Must be 'export default' with 'async queue'
export default {
  async queue(batch: MessageBatch<VoidMessage>, env: Env): Promise<void> {
    console.log(`[SSII] Received batch of ${batch.messages.length} messages`);
    
    for (const message of batch.messages) {
      try {
        const { tenantId, paddedStream, threatIntelVector } = message.body;

        // 1. Run Scoring Engine
        const result = runScoringEngine(paddedStream, threatIntelVector);

        // 2. Write to KV
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
          console.log(`[SSII] ✅ Cached: ${tenantId}`);
        }

        message.ack();
      } catch (err) {
        console.error(`[SSII] ❌ Error: ${err.message}`);
        message.retry();
      }
    }
  }
};   