// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import { runScoringEngine, type PaddedStreamNode } from './lib/scoring-engine';
import type { ExportedHandler } from '@cloudflare/workers-types';

// Definition of environment types
interface Env {
  VM_LIVE_POSTURE_CACHE: KVNamespace;
  INGESTION_SERVICE_SECRET: string;
  // Add other bindings as needed
}

// Define message payload type
interface QueuePayload {
  paddedStream: PaddedStreamNode[];
  threatIntelVector: number[];
  tenantId: string;
  originalEvent: any;
}

export default {
  // 1. HTTP Handler (Astro App)
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Delegate all HTTP requests to the Astro app
    return handle(request, env, ctx);
  },

  // 2. Queue Handler (Background Scoring)
  async queue(batch: MessageBatch<QueuePayload>, env: Env, ctx: ExecutionContext): Promise<void> {
    for (const message of batch.messages) {
      try {
        const { paddedStream, threatIntelVector, tenantId } = message.body;

        // Run heavy scoring logic here (Safe from HTTP timeouts)
        const result = runScoringEngine(paddedStream, threatIntelVector);

        // Write to KV
        if (env.VM_LIVE_POSTURE_CACHE && tenantId) {
          await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify({
            ...result,
            computedAt: new Date().toISOString()
          }));
          console.log(`[SSII] ✅ CACHED DATA FOR TENANT: ${tenantId}`);
        }

        message.ack(); // Mark as successful
      } catch (err) {
        console.error(`[SSII] ❌ Scoring failed: ${err}`);
        message.retry(); // Retry on failure
      }
    }
  },
} satisfies ExportedHandler<Env, QueuePayload>;   