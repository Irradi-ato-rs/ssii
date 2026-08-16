// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import consumer from '../workers/ssii-consumer';

export default {
  // 1. Astro Fetch Handler
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    // CRITICAL: Pass request, env, ctx in this exact order
    return handle(request, env, ctx);
  },
  
  // 2. Queue Handler
  async queue(batch: MessageBatch<any>, env: any) {
    return consumer.queue(batch, env);
  }
} satisfies ExportedHandler;   