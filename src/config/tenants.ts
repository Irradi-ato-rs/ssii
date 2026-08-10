// src/config/tenants.ts
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

// Real customer domains and their IdP tenant IDs are customer-identifying
// information and are never committed to this public repository. They
// live in a private Cloudflare KV namespace (TENANT_DIRECTORY), populated
// out-of-band by VoidMetric operators during customer onboarding. This
// function is the generic, auditable lookup logic — the data it queries
// stays private.
export async function getIdPConfig(email: string, kv: KVNamespace): Promise<IdPConfig | null> {
  const domain = parseEmailDomain(email);
  if (!domain) return null;
  const raw = await kv.get(domain);
  return raw ? (JSON.parse(raw) as IdPConfig) : null;
}

export async function getIdPConfigByDomain(domain: string, kv: KVNamespace): Promise<IdPConfig | null> {
  const raw = await kv.get(domain.toLowerCase().trim());
  return raw ? (JSON.parse(raw) as IdPConfig) : null;
}