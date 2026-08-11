// src/env.d.ts
interface Env {
  PRIVATE_ENTRA_ICLASSED_CLIENT_ID: string;
  PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET: string;
  PRIVATE_ROLE_ALLOWLIST: string;
  INGESTION_SERVICE_SECRET: string;
}

type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

declare namespace App {
  interface Locals extends Runtime {
    user?: {
      email: string;
      role: 'governance' | 'admin' | 'executive' | 'engineer';
      tenant: string;
      rawClaimsPayload: Record<string, unknown>;
    };
  }
}