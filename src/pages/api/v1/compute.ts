// src/pages/api/v1/compute.ts
export const prerender = false;
import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    // 1. Security Check (Ensure user is authenticated)
    if (!locals.user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    // 2. Parse Input
    const { matrix } = await request.json(); // Expects a 4x3 array: C[i][j]
    
    if (!matrix || !Array.isArray(matrix) || matrix.length !== 4) {
      return new Response(JSON.stringify({ error: 'Invalid matrix. Expected 4x3 array.' }), { status: 400 });
    }

    const weights = [0.4, 0.3, 0.3]; // Enabler Weights (Sum = 1.0)
    const rowValidations: number[] = new Array(4).fill(1);
    let systemicIntegrityIndex = 1;

    // 3. Compute Metric B (Geometric Product via Log-Sum for Precision)
    for (let i = 0; i < 4; i++) {
      let logSum = 0;
      let isZeroTriggered = false;

      for (let j = 0; j < 3; j++) {
        const score = matrix[i]?.[j] ?? 0;

        // Theorem 1: Zero Property (Risk Switch)
        if (score === 0) {
          isZeroTriggered = true;
          break; // Collapse row immediately
        }

        // Geometric Aggregation: ln(Product) = Sum(w * ln(x))
        logSum += weights[j] * Math.log(score);
      }

      // Finalize Row Vector Vi
      rowValidations[i] = isZeroTriggered ? 0 : Math.exp(logSum);
      
      // Update Global Systemic Index
      systemicIntegrityIndex *= rowValidations[i];
    }

    // 4. Compute Metric A (Additive Compliance)
    let metricA = 0;
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 3; j++) {
        metricA += (matrix[i]?.[j] ?? 0) * weights[j];
      }
    }
    // Normalize Metric A to [0.0, 1.0] range (Max possible sum is 4.0 if weights sum to 1 per row? 
    // Actually, if weights sum to 1.0 total, max sum is 4.0. If weights are per-row, max is 1.0 per row.
    // Your weights [0.4, 0.3, 0.3] sum to 1.0. So max row score is 1.0. Max total is 4.0.
    // Normalizing by 4 gives a 0-1 average.
    metricA = metricA / 4; 

    // 5. Audience Splitting (Executive vs Engineer)
    const responsePayload: any = {
      metric_a_compliance: Number(metricA.toFixed(4)),
      metric_b_integrity: Number(systemicIntegrityIndex.toFixed(4)),
      status: systemicIntegrityIndex === 0 ? "CRITICAL_RISK_SWITCH_TRIGGERED" : "NOMINAL"
    };

    // Engineers/Admins see the granular row data
    if (locals.user.role === 'engineer' || locals.user.role === 'admin') {
      responsePayload.row_validations = rowValidations.map(v => Number(v.toFixed(4)));
    }

    return new Response(
      JSON.stringify(responsePayload),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("Compute Error:", error);
    return new Response(JSON.stringify({ error: "Malformed payload matrix." }), { status: 400 });
  }
};   