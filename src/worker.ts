// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import consumer from '../workers/ssii-consumer';

export default {
  // 1. Astro Fetch Handler (SSR, Middleware, API Routes)
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    // CRITICAL: Pass ONLY (request, env, ctx) for Astro 6
    // Do NOT pass manifest or app (Astro 5 pattern)
    return handle(request, env, ctx);
  },
  
  // 2. Queue Handler (VoidMetric Processing)
  async queue(batch: MessageBatch<any>, env: any) {
    return consumer.queue(batch, env);
  }
} satisfies ExportedHandler;   