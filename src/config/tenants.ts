// src/config/tenants.ts
export interface IdPConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  authMethod?: 'client_secret_basic' | 'client_secret_post';
  // Optional: OIDC end-session endpoint (RP-Initiated Logout, per the
  // OIDC Session Management spec). Not every IdP exposes one — if absent,
  // signout.ts falls back to local-only logout.
  endSessionEndpoint?: string;
}

const tenants: Record<string, IdPConfig> = {
  "iclassed.com": {
    issuer: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/v2.0",
    authorizationEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/authorize",
    tokenEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/token",
    jwksUri: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/discovery/v2.0/keys",
    endSessionEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/logout",
    clientIdEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_ID",
    clientSecretEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET",
    authMethod: 'client_secret_post',
  },
  "fzoirm.com": {
    issuer: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/v2.0",
    authorizationEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/authorize",
    tokenEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/token",
    jwksUri: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/discovery/v2.0/keys",
    endSessionEndpoint: "https://login.microsoftonline.com/442355f4-8c8f-4101-ae2a-3db0ca8d44ac/oauth2/v2.0/logout",
    clientIdEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_ID",
    clientSecretEnv: "PRIVATE_ENTRA_ICLASSED_CLIENT_SECRET",
    authMethod: 'client_secret_post',
  },
  // Example shape for a future non-Microsoft IdP (Okta, Google, Auth0, etc.)
  // — nothing else in the codebase needs to change to onboard one:
  //
  // "example-okta-tenant.com": {
  //   issuer: "https://your-org.okta.com/oauth2/default",
  //   authorizationEndpoint: "https://your-org.okta.com/oauth2/default/v1/authorize",
  //   tokenEndpoint: "https://your-org.okta.com/oauth2/default/v1/token",
  //   jwksUri: "https://your-org.okta.com/oauth2/default/v1/keys",
  //   endSessionEndpoint: "https://your-org.okta.com/oauth2/default/v1/logout",
  //   clientIdEnv: "PRIVATE_OKTA_EXAMPLE_CLIENT_ID",
  //   clientSecretEnv: "PRIVATE_OKTA_EXAMPLE_CLIENT_SECRET",
  //   authMethod: "client_secret_post",
  // },
};

function parseEmailDomain(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase().trim();
}

export function getIdPConfig(email: string): IdPConfig | null {
  const domain = parseEmailDomain(email);
  if (!domain) return null;
  return tenants[domain] || null;
}

// New: direct lookup by domain, for callers (like signout) that already
// know the domain and don't have an email to parse.
export function getIdPConfigByDomain(domain: string): IdPConfig | null {
  return tenants[domain.toLowerCase().trim()] || null;
}