// src/config/tenants.ts
export interface IdPConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  endSessionEndpoint?: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

// Remove hardcoded tenants object entirely
// Fetch from KV at runtime
export async function getIdPConfig(
  env: { VM_TENANT_DIRECTORY: KVNamespace },
  email: string
): Promise<IdPConfig | null> {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  const domain = email.slice(at + 1).toLowerCase().trim();
  
  const config = await env.VM_TENANT_DIRECTORY.get(domain, 'json');
  return config as IdPConfig | null;
}

export async function getIdPConfigByDomain(
  env: { VM_TENANT_DIRECTORY: KVNamespace },
  domain: string
): Promise<IdPConfig | null> {
  const config = await env.VM_TENANT_DIRECTORY.get(domain.toLowerCase().trim(), 'json');
  return config as IdPConfig | null;
}   