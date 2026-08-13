// src/lib/worker-exports.ts
import { DurableObject } from "cloudflare:workers";
import { runScoringEngine } from "./scoring-engine";

// Export PostureObject (Wrangler will find this in the bundle)
export class PostureObject extends DurableObject {
  constructor(ctx: DurableObjectState, env: any) {
    super(ctx, env);
    this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS posture (
          tenant_id TEXT PRIMARY KEY,
          metric_a REAL,
          metric_b REAL,
          status TEXT,
          updated_at INTEGER
        )
      `);
    });
  }

  async updatePosture(data: { tenantId: string, metric_a: number, metric_b: number, status: string }) {
    this.ctx.storage.sql.exec(
      `INSERT OR REPLACE INTO posture (tenant_id, metric_a, metric_b, status, updated_at) VALUES (?, ?, ?, ?, ?)`,
      data.tenantId, data.metric_a, data.metric_b, data.status, Date.now()
    );
    return { success: true };
  }
}

// Export SsiiService
export class SsiiService {
  constructor(private ctx: ExecutionContext, private env: any) {}
  async computeAndStore(data: { tenantId: string, paddedStream: any[], threatIntelVector: number[] }) {
    const result = runScoringEngine(data.paddedStream, data.threatIntelVector);
    const id = this.env.POSTURE_DO.idFromName(data.tenantId);
    const stub = this.env.POSTURE_DO.get(id);
    await stub.updatePosture({
      tenantId: data.tenantId,
      metric_a: result.metric_a_compliance,
      metric_b: result.metric_b_integrity,
      status: result.status
    });
    return result;
  }
}   