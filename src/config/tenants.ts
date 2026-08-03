// src/config/tenants.ts

export interface IdPConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientIdEnv: string;
  clientSecretEnv: string;
}

const tenants: Record<string, IdPConfig> = {
  // --- Existing Okta Example ---
  "example.com": {
    issuer: "https://dev-123456.okta.com/oauth2/default",
    authorizationEndpoint: "https://dev-123456.okta.com/oauth2/default/v1/authorize",
    tokenEndpoint: "https://dev-123456.okta.com/oauth2/default/v1/token",
    jwksUri: "https://dev-123456.okta.com/oauth2/default/v1/keys",
    clientIdEnv: "PRIVATE_OKTA_CLIENT_ID",
    clientSecretEnv: "PRIVATE_OKTA_CLIENT_SECRET",
  },

  // --- NEW: Entra ID (Microsoft) for iclassed.com ---
  "iclassed.com": {
    // Tenant ID is now hardcoded directly in the URLs below
    issuer: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/v2.0",
    authorizationEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/authorize",
    tokenEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/token",
    jwksUri: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/discovery/v2.0/keys",
    clientIdEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_ID",
    clientSecretEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET"
  }   
};

export function getIdPConfig(email: string): IdPConfig | null {
  const domain = email.split('@')[1].toLowerCase();
  const config = tenants[domain];
  
  // Simple lookup, no dynamic replacement needed since IDs are hardcoded
  return config || null;
}   