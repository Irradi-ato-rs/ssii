// src/env.d.ts
type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

// 1. Define Cloudflare Bindings (KV, Secrets, Assets)
interface Env {
  // KV Namespaces (must match wrangler.jsonc binding names exactly)
  VM_TENANT_DIRECTORY: KVNamespace;
  VM_PROPRIETARY_PARSERS: KVNamespace;
  SESSION: KVNamespace;

  // Secrets (injected via `wrangler secret put`)
  PRIVATE_ENTRA_ICLASSED_CLIENT_ID: string;
  PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET: string;
  // Add other tenant secrets here as needed (e.g., PRIVATE_ENTRA_FZOIRM_...)

  // Assets (from wrangler.jsonc)
  ASSETS: Fetcher;
}

// 2. Define App Locals (Your original user/session types)
declare namespace App {
  interface Locals extends Runtime {
    user?: {
      email: string;
      role: 'governance' | 'admin' | 'executive' | 'engineer';
      tenant: string;
      // Raw decoded id_token claims
      rawClaimsPayload: Record<string, unknown>;
    };
  }
}   