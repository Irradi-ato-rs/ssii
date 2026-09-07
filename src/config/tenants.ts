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

export type TenantTier = 'enterprise' | 'self-serve';

// Single IdP for all users (env-based)
export function getIdPConfig(env: { VM_TENANT_DIRECTORY: KVNamespace } & Record<string, string>, email: string): Promise<IdPConfig | null> {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return Promise.resolve(null);
  const domain = email.slice(at + 1).toLowerCase().trim();

  return getIdPConfigByDomain(env, domain);
}

export async function getIdPConfigByDomain(
  env: { VM_TENANT_DIRECTORY: KVNamespace } & Record<string, string>,
  domain: string
): Promise<IdPConfig | null> {
  const raw = await env.VM_TENANT_DIRECTORY.get(domain.toLowerCase().trim());
  if (raw) return JSON.parse(raw) as IdPConfig;

  // Self-serve fallback: no KV record → use default IdP from env
  const clientId = env.PRIVATE_ENTRA_ICLASSED_CLIENT_ID?.trim();
  if (!clientId) return null;

  return {
    issuer: env.IDP_ISSUER?.trim() || '',
    authorizationEndpoint: env.IDP_AUTH_ENDPOINT?.trim() || '',
    tokenEndpoint: env.IDP_TOKEN_ENDPOINT?.trim() || '',
    jwksUri: env.IDP_JWKS_URI?.trim() || '',
    endSessionEndpoint: env.IDP_END_SESSION_ENDPOINT?.trim() || undefined,
    clientIdEnv: 'PRIVATE_ENTRA_ICLASSED_CLIENT_ID',
    clientSecretEnv: 'PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET',
    authMethod: 'client_secret_basic',
  };
}

export async function getTenantTier(
  env: { VM_TENANT_DIRECTORY: KVNamespace },
  domain: string
): Promise<TenantTier> {
  const raw = await env.VM_TENANT_DIRECTORY.get(`tenant:${domain.toLowerCase().trim()}`);
  return raw ? 'enterprise' : 'self-serve';
}   