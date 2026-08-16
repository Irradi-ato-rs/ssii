// src/worker.ts
import type { SSRManifest } from 'astro';
import { App } from 'astro/app';
import { handle } from '@astrojs/cloudflare/handler';
import consumer from '../workers/ssii-consumer';

export function createExports(manifest: SSRManifest) {
  const app = new App(manifest);
  
  return {
    default: {
      // 1. Astro Fetch Handler receiving full manifest context
      async fetch(request: Request, env: any, ctx: any) {
        return handle(manifest, app, request, env, ctx);
      },
      
      // 2. Queue Handler matching the same deployment container
      async queue(batch: any, env: any) {
        return consumer.queue(batch, env);
      }
    }
  };
}
