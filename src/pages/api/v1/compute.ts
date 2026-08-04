export const prerender = false;
import type { APIRoute } from 'astro';

// System Architect Configurations (V3.0 Unified Weights & Vectors)
const PRIORITY_ALPHA = [0.50, 0.30, 0.15, 0.05]; // Row weights: C1 (Identity) is 50% of the risk profile
const BASE_ENABLER_WEIGHTS = [0.4, 0.3, 0.3];  // Column weights: E1, E2, E3
const EPSILON = 1e-6;                            // Harmonic visibility floor constant
const S_CURVE_STEEPNESS = 10.0;                  // k-index for sigmoidal failure transitions
const S_CURVE_MIDPOINT = 0.5;                    // x0 inflection point for systemic perimeter breach

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    // 1. Security Check (Ensure user is authenticated)
    if (!locals.user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    // 2. Parse Input Payload
    // Supports direct matrix array input or advanced v3 objects carrying time metrics
    const body = await request.json();
    const rawMatrix = Array.isArray(body) ? body : body.matrix;
    const threatIntel = body.threatIntelVector || [0.0, 0.0, 0.0]; // Dynamic E1, E2, E3 threat multipliers
    const heartbeats = body.telemetryHeartbeats;                   // Optional matrix of epoch timestamps
    const criticality = body.criticalityCoefficients;              // Optional matrix of asset tiers (1-3)

    if (!rawMatrix || !Array.isArray(rawMatrix) || rawMatrix.length !== 4) {
      return new Response(JSON.stringify({ error: 'Invalid matrix. Expected 4x3 array.' }), { status: 400 });
    }

    const now = Math.floor(Date.now() / 1000);

    // --- PHASE A: CONTEXT-AWARE WEIGHT RE-ALLOCATION ---
    // Shifts column focus dynamically based on active external threat feeds
    const dynamicWeights = BASE_ENABLER_WEIGHTS.map((w, j) => w * (1 + 1.8 * (threatIntel[j] || 0)));
    const weightSum = dynamicWeights.reduce((a, b) => a + b, 0);
    const normalizedWeights = dynamicWeights.map(w => w / (weightSum || 1));

    // --- PHASE B: STOCHASTIC BAYESIAN DRIFT & ENTROPY DECAY ---
    // Degrades trust parameters over time if active validation signals are missing
    const driftedMatrix: number[][] = Array(4).fill(0).map(() => Array(3).fill(0));

    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 3; j++) {
        const baseValue = rawMatrix[i]?.[j] ?? 0;

        // Compute delta time in hours since last validation scan
        const lastSeen = heartbeats?.[i]?.[j] ?? now;
        const dt = Math.max(0, (now - lastSeen) / 3600);

        const coefficient = criticality?.[i]?.[j] ?? 1.0;
        const driftVolatility = 0.02 * coefficient;
        const structuralEntropy = 0.005 * dt;
        const expectedDecay = baseValue - structuralEntropy - (driftVolatility * Math.sqrt(dt));

        driftedMatrix[i][j] = Math.max(0.0001, Math.min(1.0, expectedDecay));
      }
    }

    // --- PHASE C: NON-LINEAR SIGMOIDAL SATURATION TRANSFORM ---
    // Maps scores to an S-curve to isolate structural tipping points
    const sigmoidalMatrix: number[][] = Array(4).fill(0).map(() => Array(3).fill(0));

    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 3; j++) {
        const v = driftedMatrix[i][j];
        sigmoidalMatrix[i][j] = 1 / (1 + Math.exp(-S_CURVE_STEEPNESS * (v - S_CURVE_MIDPOINT)));
      }
    }

    // --- PHASE D: MATRIX SPECTRAL TOPOLOGY RESONANCE ANALYSIS ---
    // Constructs a covariance matrix to flag aligned vulnerabilities
    const covariance: number[][] = Array(4).fill(0).map(() => Array(4).fill(0));
    for (let i = 0; i < 4; i++) {
      for (let p = 0; p < 4; p++) {
        let dotProduct = 0;
        for (let j = 0; j < 3; j++) {
          dotProduct += (1 - sigmoidalMatrix[i][j]) * (1 - sigmoidalMatrix[p][j]);
        }
        covariance[i][p] = dotProduct;
      }
    }

    // Edge-optimized Power Iteration method to isolate the Principal Eigenvalue in < 1ms
    let eigenVector = [1.0, 1.0, 1.0, 1.0];
    let principalEigenvalue = 0;

    for (let iter = 0; iter < 8; iter++) {
      const nextVector = [0.0, 0.0, 0.0, 0.0];
      for (let i = 0; i < 4; i++) {
        for (let p = 0; p < 4; p++) {
          nextVector[i] += covariance[i][p] * eigenVector[p];
        }
      }
      const norm = Math.sqrt(nextVector.reduce((sum, v) => sum + v * v, 0));
      principalEigenvalue = norm;
      eigenVector = nextVector.map(v => v / (norm || 1));
    }

    const trace = covariance[0][0] + covariance[1][1] + covariance[2][2] + covariance[3][3];
    const chaosPenalty = Math.max(0, (principalEigenvalue - (trace / 4)) * 0.25);

    // --- PHASE E: DUAL-ENGINE STRUCTURAL METRIC COMPUTE ---
    // Metric A: Continuous Maturity Matrix (Normalized Multi-Dimensional Additive Summation)
    let metricA = 0;
    for (let i = 0; i < 4; i++) {
      let rowSum = 0;
      for (let j = 0; j < 3; j++) {
        rowSum += sigmoidalMatrix[i][j] * normalizedWeights[j];
      }
      metricA += rowSum * PRIORITY_ALPHA[i];
    }

    // Metric B: Gradient-Preserving Harmonic Mean with Dynamic Priority Vectors
    let harmonicDenominator = 0;
    const rowValidations: number[] = [];

    for (let i = 0; i < 4; i++) {
      let rowLogSum = 0;
      for (let j = 0; j < 3; j++) {
        rowLogSum += normalizedWeights[j] * Math.log(sigmoidalMatrix[i][j] || 0.0001);
      }
      const v_i = Math.exp(rowLogSum);
      rowValidations.push(v_i);

      harmonicDenominator += PRIORITY_ALPHA[i] / (v_i + EPSILON);
    }

    const rawSiLiveHarmonic = 1.0 / harmonicDenominator;
    // Deduct the spectral chaos penalty factor
    const scoreB_Final = Math.max(0.0001, rawSiLiveHarmonic - chaosPenalty);

    // 5. Audience Splitting Output Execution
    const responsePayload: any = {
      metric_a_compliance: Number(metricA.toFixed(4)),
      metric_b_integrity: Number(scoreB_Final.toFixed(4)),
      status: scoreB_Final < 0.20 ? "CRITICAL_RISK_SWITCH_TRIGGERED" : "NOMINAL",
      theater_gap_delta: Number((metricA - scoreB_Final).toFixed(4))
    };

    // Engineers/Admins see the granular matrix telemetry and spectral array indexes
    if (locals.user.role === 'engineer' || locals.user.role === 'admin') {
      responsePayload.row_validations = rowValidations.map(v => Number(v.toFixed(4)));
      responsePayload.spectral_analysis = {
        chaos_index_penalty: Number(chaosPenalty.toFixed(5)),
        principal_eigenvalue: Number(principalEigenvalue.toFixed(5)),
        resonance_exploit_chain_detected: chaosPenalty > 0.15
      };
      responsePayload.matrix_state_view = {
        sigmoidal_transformed: sigmoidalMatrix.map(row => row.map(v => Number(v.toFixed(4)))),
        allocated_context_weights: normalizedWeights.map(w => Number(w.toFixed(4)))
      };
    }

    return new Response(
      JSON.stringify(responsePayload),
                        { status: 200, headers: { "Content-Type": "application/json", "X-VoidMetric-Engine": "v3.0-Spectral" } }
    );

  } catch (error) {
    console.error("Compute Error:", error);
    return new Response(JSON.stringify({ error: "Malformed payload matrix." }), { status: 400 });
  }
};
