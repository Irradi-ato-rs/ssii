// src/env.d.ts
type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

// 1. Define Cloudflare Bindings (KV, Secrets, Assets)
interface Env {
  // KV Namespaces (must match wrangler.jsonc binding names exactly)
  VM_TENANT_DIRECTORY: KVNamespace;    // Per-domain IdPConfig records — actual tenant onboarding data lives here, never in source.
  VM_PROPRIETARY_PARSERS: KVNamespace; // f_norm normalization logic/config. Trade-secret boundary — read only from PRIVATE_INGESTION_CORE.
  SESSION: KVNamespace;                // Reserved. Purpose not yet finalized — not currently read or written anywhere in this codebase.

  // Secrets (injected via `wrangler secret put`)
  PRIVATE_ENTRA_ICLASSED_CLIENT_ID: string;
  PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET: string;
  // Add other tenant secrets here as needed (e.g., PRIVATE_ENTRA_FZOIRM_...)

  PRIVATE_ROLE_ALLOWLIST: string; // JSON-encoded { role: [email, ...] } map. Set via `wrangler secret put`, never committed.

  // Distinguishes an authoritative call from PRIVATE_INGESTION_CORE from
  // a browser-submitted sandbox run against /api/compute. Both services
  // share the "ssii" Cloudflare account; this is a same-account internal
  // marker, not a network-forgery defense — that guarantee will come from
  // a Service Binding if/when compute.ts's authoritative path is split
  // into its own unlisted Worker. Set via `wrangler secret put`.
  INGESTION_SERVICE_SECRET: string;

  // Assets (from wrangler.jsonc)
  ASSETS: Fetcher;
}

// 2. Define App Locals (user/session types)
declare namespace App {
  interface Locals extends Runtime {
    user?: {
      email: string;
      role: 'governance' | 'admin' | 'executive' | 'engineer';
      tenant: string;
      // Raw decoded id_token claims — server-side use only; never pass
      // directly into a template/component prop.
      rawClaimsPayload: Record<string, unknown>;
    };
  }
}