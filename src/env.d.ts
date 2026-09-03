// src/env.d.ts
interface Env {
  PRIVATE_ENTRA_ICLASSED_CLIENT_ID: string;
  PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET: string;
  PRIVATE_ROLE_ALLOWLIST: string;
  PRIVATE_SESSION_SECRET: string;
  INGESTION_SERVICE_SECRET: string;
  VM_TENANT_DIRECTORY: KVNamespace;
}

type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

declare namespace App {
  interface Locals {
    user?: {
      sub: string;
      email: string;
      role: 'governance' | 'admin' | 'executive' | 'engineer' | 'operator';
      tenant: string;
      rawClaimsPayload?: Record<string, unknown>;
    };
    tenantId?: string;
    portalRecord?: Record<string, unknown>;
  }
}