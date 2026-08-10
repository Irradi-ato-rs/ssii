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

// Use 'Env' type from your env.d.ts for consistency, or keep explicit interface
export async function getIdPConfig(
  env: { VM_TENANT_DIRECTORY: KVNamespace }, // ✅ Valid if @cloudflare/workers-types is installed
  email: string
): Promise<IdPConfig | null> {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  const domain = email.slice(at + 1).toLowerCase().trim();
  
  // Add null check in case key is missing in KV
  const raw = await env.VM_TENANT_DIRECTORY.get(domain);
  if (!raw) return null;

  return JSON.parse(raw) as IdPConfig;
}

export async function getIdPConfigByDomain(
  env: { VM_TENANT_DIRECTORY: KVNamespace },
  domain: string
): Promise<IdPConfig | null> {
  const raw = await env.VM_TENANT_DIRECTORY.get(domain.toLowerCase().trim());
  if (!raw) return null;
  
  return JSON.parse(raw) as IdPConfig;
}   