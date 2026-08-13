// src/worker.ts
import { workerEntrypoint } from "@astrojs/cloudflare/entrypoints/server";
import { PostureObject } from "./posture-object";
import { runScoringEngine } from "./lib/scoring-engine";

// Export Astro Handler (for frontend requests)
export default workerEntrypoint;

// Export Durable Object (for void RPC)
export { PostureObject };

// Define the RPC Service Class
export class SsiiService {
  constructor(private ctx: ExecutionContext, private env: any) {}

  async computeAndStore(data: { tenantId: string, paddedStream: any[], threatIntelVector: number[] }) {
    // 1. Run Scoring
    const result = runScoringEngine(data.paddedStream, data.threatIntelVector);

    // 2. Get Durable Object Stub
    const id = this.env.POSTURE_DO.idFromName(data.tenantId);
    const stub = this.env.POSTURE_DO.get(id);

    // 3. Update Ephemeral State
    await stub.updatePosture({
      tenantId: data.tenantId,
      metric_a: result.metric_a_compliance,
      metric_b: result.metric_b_integrity,
      status: result.status
    });

    return result;
  }
}   