// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import consumer from '../workers/ssii-consumer';

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    // CRITICAL: Pass request, env, ctx in this EXACT order
    // Do NOT pass manifest or app instances (Astro 5 pattern)
    return handle(request, env, ctx);
  },
  
  async queue(batch: MessageBatch<any>, env: any) {
    return consumer.queue(batch, env);
  }
} satisfies ExportedHandler;   