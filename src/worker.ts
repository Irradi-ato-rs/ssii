// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import { runScoringEngine, type PaddedStreamNode } from './lib/scoring-engine';
import type { ExportedHandler } from '@cloudflare/workers-types';

interface Env {
  VM_LIVE_POSTURE_CACHE: KVNamespace;
  INGESTION_SERVICE_SECRET: string;
  ASSETS: Fetcher;
}

interface QueuePayload {
  paddedStream: PaddedStreamNode[];
  threatIntelVector: number[];
  tenantId: string;
  originalEvent: any;
}

export default {
  // 1. HTTP Handler (Astro App)
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // FIX: Do NOT pass manifest. Astro 6 handle() manages this internally.
    return handle(request, env, ctx);
  },

  // 2. Queue Handler (Background Scoring)
  async queue(batch: MessageBatch<QueuePayload>, env: Env, ctx: ExecutionContext): Promise<void> {
    for (const message of batch.messages) {
      try {
        const { paddedStream, threatIntelVector, tenantId } = message.body;
        
        const result = runScoringEngine(paddedStream, threatIntelVector);

        if (env.VM_LIVE_POSTURE_CACHE && tenantId) {
          await env.VM_LIVE_POSTURE_CACHE.put(tenantId, JSON.stringify({
            ...result,
            computedAt: new Date().toISOString()
          }));
          console.log(`[SSII] ✅ CACHED DATA FOR TENANT: ${tenantId}`);
        }
        message.ack();
      } catch (err) {
        console.error(`[SSII] ❌ Scoring failed: ${err}`);
        message.retry();
      }
    }
  },
} satisfies ExportedHandler<Env, QueuePayload>;   