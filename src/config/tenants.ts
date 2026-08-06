// src/config/tenants.ts

export interface IdPConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
}

const tenants: Record<string, IdPConfig> = {
  // --- Entra ID onboard for ---
  "iclassed.com": {
    issuer: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/v2.0",
    authorizationEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/authorize",
    tokenEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/token",
    jwksUri: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/discovery/v2.0/keys",
    clientIdEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_ID",
    clientSecretEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET",
    authMethod: 'client_secret_post' // Explicitly use POST body for secrets
  },

  // --- ALLOW domain check ---
  "fzoirm.com": {
    issuer: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/v2.0",
    authorizationEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/authorize",
    tokenEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/token",
    jwksUri: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/discovery/v2.0/keys",
    clientIdEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_ID",
    clientSecretEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET",
    authMethod: 'client_secret_post'
  }
};

export function getIdPConfig(email: string): IdPConfig | null {
  if (!email || !email.includes('@')) return null;
  
  const domain = email.split('@')[1].toLowerCase();
  const config = tenants[domain];
  
  return config || null;
}   