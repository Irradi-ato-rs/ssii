// src/worker.ts
import { handle } from '@astrojs/cloudflare/handler';
import consumer from '../workers/ssii-consumer';

export default {
  async fetch(request: Request, env: any, ctx: ExecutionContext) {
    return handle(request, env, ctx);
  },
  async queue(batch: MessageBatch<any>, env: any) {
    return consumer.queue(batch, env);
  }
} satisfies ExportedHandler;   