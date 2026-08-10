type Runtime = import("@astrojs/cloudflare").Runtime<Env>;

declare namespace App {
  interface Locals extends Runtime {
    user?: {
      email: string;
      role: 'admin' | 'executive' | 'engineer';
      tenant: string;
      rawClaimsPayload: any;
    };
  }
}
