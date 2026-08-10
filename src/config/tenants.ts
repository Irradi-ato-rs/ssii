// src/config/tenants.ts
import type { KVNamespace } from '@cloudflare/workers-types';

export interface IdPConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
  endSessionEndpoint?: string;
}

function parseEmailDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase().trim();
}

// SECURE: Fetches config from Cloudflare KV (VM_TENANT_DIRECTORY)
export async function getIdPConfig(email: string, kv: KVNamespace): Promise<IdPConfig | null> {
  const domain = parseEmailDomain(email);
  if (!domain) return null;
  
  const raw = await kv.get(domain);
  if (!raw) return null;

  try {
    return JSON.parse(raw) as IdPConfig;
  } catch (e) {
    console.error(`[TenantConfig] Failed to parse config for ${domain}`, e);
    return null;
  }
}

export async function getIdPConfigByDomain(domain: string, kv: KVNamespace): Promise<IdPConfig | null> {
  const raw = await kv.get(domain.toLowerCase().trim());
  if (!raw) return null;

  try {
    return JSON.parse(raw) as IdPConfig;
  } catch (e) {
    console.error(`[TenantConfig] Failed to parse config for ${domain}`, e);
    return null;
  }
}   