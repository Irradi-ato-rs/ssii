// workers/ssii-consumer.ts
// Zero-persistence: pure computation + structured log + posture cache.
import { runScoringEngine, type PaddedStreamNode, type EngineParams } from '../src/lib/scoring-engine';

export interface Env {
  VM_LIVE_POSTURE_CACHE: KVNamespace;
}

export interface VoidMessage {
  type: 'signal_update';
  tenantId: string;
  paddedStream: PaddedStreamNode[];
  threatIntelVector: number[];
  previousStream?: PaddedStreamNode[];
  previousThreatIntelVector?: number[];
  hyperparams?: Partial<EngineParams>;
  timestamp: number;
}

export default {
  async queue(batch: MessageBatch<VoidMessage>, env: Env): Promise<void> {
    console.log(`[SSII] Received batch of ${batch.messages.length} messages`);

    for (const message of batch.messages) {
      try {
        const body = message.body;

        if (!body.paddedStream || !Array.isArray(body.paddedStream)) {
          console.warn(`[SSII] ⚠️ Invalid message format. Missing paddedStream. Acking to skip.`, body);
          message.ack();
          continue;
        }

        const {
          paddedStream,
          threatIntelVector,
          previousStream,
          previousThreatIntelVector,
          hyperparams,
        } = body;

        const result = runScoringEngine(
          paddedStream,
          threatIntelVector || [0, 0, 0],
          previousStream,
          previousThreatIntelVector,
          hyperparams
        );

        // Write posture cache (TTL 24h)
        await env.VM_LIVE_POSTURE_CACHE.put(
          `posture:${body.tenantId}`,
          JSON.stringify({ ...result, timestamp: body.timestamp }),
          { expirationTtl: 86400 }
        );

        console.log(`[SSII] ✅ Computed: ${body.tenantId}`, {
          metric_a: result.metric_a_compliance,
          metric_a_velocity: result.metric_a_velocity,
          metric_b: result.metric_b_integrity,
          status: result.status,
          wi: result.watermelon_index,
          hf: result.honest_failure_index,
          params: hyperparams ? "custom" : "default",
        });

        message.ack();
      } catch (err) {
        console.error(`[SSII] ❌ Critical Error: ${(err as Error).message}`, message.body);
        message.retry();
      }
    }
  },
  async fetch(): Promise<Response> {
    return new Response("SSII Consumer Active", { status: 200 });
  }
};