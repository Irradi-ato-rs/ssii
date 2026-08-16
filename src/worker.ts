// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import consumer from '../workers/ssii-consumer';

export default {
  // 1. Astro Fetch Handler (SSR, Middleware, API Routes)
  async fetch(request: Request, env: any, ctx: any) {
    // CRITICAL: Must return the result of handle()
    return handle(request, env, ctx);
  },
  
  // 2. Queue Handler (VoidMetric Processing)
  async queue(batch: MessageBatch<any>, env: any) {
    return consumer.queue(batch, env);
  }
} satisfies ExportedHandler;   