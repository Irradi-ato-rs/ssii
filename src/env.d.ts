type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

declare namespace App {
  interface Locals extends Runtime {
    user?: {
      email: string;
      role: 'governance' | 'admin' | 'executive' | 'engineer';
      tenant: string;
      // Raw decoded id_token claims — kept for audit/debug purposes.
      // Server-side use only; never pass this object directly into a
      // template/component prop.
      rawClaimsPayload: Record<string, unknown>;
    };
  }
}