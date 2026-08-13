// src/posture-object.ts
import { DurableObject } from "cloudflare:workers";

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
      `INSERT OR REPLACE INTO posture (tenant_id, metric_a, metric_b, status, updated_at) 
       VALUES (?, ?, ?, ?, ?)`,
      data.tenantId, data.metric_a, data.metric_b, data.status, Date.now()
    );
    return { success: true };
  }

  async getPosture(tenantId: string) {
    const result = this.ctx.storage.sql
      .exec("SELECT * FROM posture WHERE tenant_id = ?", tenantId)
      .one();
    
    if (!result) return null;

    return {
      metric_a_compliance: result.metric_a,
      metric_b_integrity: result.metric_b,
      status: result.status,
      computedAt: new Date(result.updated_at).toISOString()
    };
  }
}   