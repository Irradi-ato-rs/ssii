// src/pages/api/compute.ts
export const prerender = false;
import type { APIRoute } from 'astro';

// System Architect Configurations (V3.0 Unified Exponent and Priority Matrices)
const PRIORITY_ALPHA = [0.50, 0.30, 0.15, 0.05];
const BASE_ENABLER_WEIGHTS = [0.4, 0.3, 0.3];
const EPSILON = 1e-6;
const S_CURVE_STEEPNESS = 10.0;
const S_CURVE_MIDPOINT = 0.5;

interface PaddedStreamNode {
  maskedValue: number;
  evaluationWeight: number;
  capabilityPriority: number;
  lastTelemetryHeartbeat: number;
}

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    // 1. Security Check: Enforce structural user authentication context boundaries
    if (!locals.user) {
      return new Response(JSON.stringify({ error: 'Unauthorized payload transmission rejection.' }), { status: 401 });
    }
    
    // 2. Parse Input Payload
    const body = await request.json();
    const paddedStream = body.paddedStream as PaddedStreamNode[];
    const threatIntel = body.threatIntelVector || [0.0, 0.0, 0.0];
    
    if (!paddedStream || !Array.isArray(paddedStream) || paddedStream.length !== 32) {
      return new Response(JSON.stringify({ error: 'Invalid payload matrix. Expected a padded 32-element array stream.' }), { status: 400 });
    }
    
    const now = Math.floor(Date.now() / 1000);
    
    // --- PHASE A: CONTEXT-AWARE WEIGHT RE-ALLOCATION ---
    const dynamicWeights = BASE_ENABLER_WEIGHTS.map((w, j) => w * (1 + 1.8 * (threatIntel[j] || 0)));
    const weightSum = dynamicWeights.reduce((a, b) => a + b, 0);
    const normalizedWeights = dynamicWeights.map(w => w / (weightSum || 1));
    
    const reconstructedSigmoidalMatrix: number[][] = Array(4).fill(0).map(() => Array(3).fill(1.0));
    
    let scoreA_Accumulator = 0;
    let systemicPriorityWeightAccumulator = 0;
    let harmonicDenominator = 0;
    let criticalBreakerTripped = false;
    
    // --- PHASE B: COMMUTATIVE MATRIX PROCESSING LOOP ---
    paddedStream.forEach((node) => {
      const baseValue = node.maskedValue;
      const w_base = node.evaluationWeight;
      const alpha_base = node.capabilityPriority;
      
      if (alpha_base * w_base === 0) return;
      
      const j_col = BASE_ENABLER_WEIGHTS.indexOf(w_base);
      const i_row = PRIORITY_ALPHA.indexOf(alpha_base);
      const activeWeight = j_col !== -1 ? normalizedWeights[j_col] : w_base;
      const activePriority = i_row !== -1 ? PRIORITY_ALPHA[i_row] : alpha_base;
      
      const dt = Math.max(0, (now - node.lastTelemetryHeartbeat) / 3600);
      const driftVolatility = 0.04;
      const expectedDecay = baseValue - (0.005 * dt) - (driftVolatility * Math.sqrt(dt));
      const driftedScore = Math.max(0.0001, Math.min(1.0, expectedDecay));
      
      const sigmoidalScore = 1 / (1 + Math.exp(-S_CURVE_STEEPNESS * (driftedScore - S_CURVE_MIDPOINT)));
      
      if (i_row !== -1 && j_col !== -1) {
        reconstructedSigmoidalMatrix[i_row][j_col] = sigmoidalScore;
      }
      
      scoreA_Accumulator += (sigmoidalScore * activeWeight * activePriority);
      systemicPriorityWeightAccumulator += (activeWeight * activePriority);
      
      if (sigmoidalScore < 0.05) {
        criticalBreakerTripped = true;
      }
    });
    
    // --- PHASE C: COVARIANCE MATRIX SPECTRAL TOPOLOGY ANALYSIS ---
    const covariance: number[][] = Array(4).fill(0).map(() => Array(4).fill(0));
    for (let i = 0; i < 4; i++) {
      for (let p = 0; p < 4; p++) {
        let dotProduct = 0;
        for (let j = 0; j < 3; j++) {
          dotProduct += (1 - reconstructedSigmoidalMatrix[i][j]) * (1 - reconstructedSigmoidalMatrix[p][j]);
        }
        covariance[i][p] = dotProduct;
      }
    }
    
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
    const chaosIndexPenalty = Math.max(0, (principalEigenvalue - (trace / 4)) * 0.25);
    
    // --- PHASE D: COMPILING COMPUTE INDICES AND METRIC NORMALIZATIONS ---
    const finalScoreA = scoreA_Accumulator / (systemicPriorityWeightAccumulator || 1);
    
    const finalRowValidations = reconstructedSigmoidalMatrix.map((row, i) => {
      let rowLogSum = 0;
      for (let j = 0; j < 3; j++) {
        rowLogSum += normalizedWeights[j] * Math.log(row[j] || 0.0001);
      }
      const v_i = Math.exp(rowLogSum);
      harmonicDenominator += PRIORITY_ALPHA[i] / (v_i + EPSILON);
      return v_i;
    });
    
    const rawSiLiveHarmonic = 1.0 / (harmonicDenominator + EPSILON);
    let finalScoreB = Math.max(0.0001, rawSiLiveHarmonic - chaosIndexPenalty);
    
    if (criticalBreakerTripped) {
      finalScoreB = Math.min(finalScoreB, 0.015);
    }
    
    // --- PHASE E: SECURE MULTI-ROLE DISPATCHER ---
    const responsePayload: any = {
      metric_a_compliance: Number(finalScoreA.toFixed(4)),
      metric_b_integrity: Number(finalScoreB.toFixed(4)),
      status: finalScoreB < 0.20 ? "CRITICAL_RISK_SWITCH_TRIGGERED" : "NOMINAL",
      theater_gap_delta: Number((finalScoreA - finalScoreB).toFixed(4))
    };
    
    // Advanced telemetry tracing for engineering/admin roles only
    // Ensure locals.user has the 'role' claim from your Entra ID Token
    const userRole = (locals.user as any)?.role;
    if (userRole === 'engineer' || userRole === 'admin') {
      responsePayload.row_validations = finalRowValidations.map(v => Number(v.toFixed(4)));
      responsePayload.spectral_analysis = {
        chaos_index_penalty: Number(chaosIndexPenalty.toFixed(5)),
        principal_eigenvalue: Number(principalEigenvalue.toFixed(5)),
        resonance_exploit_chain_detected: chaosIndexPenalty > 0.15
      };
    }
    
    return new Response(
      JSON.stringify(responsePayload),
      { status: 200, headers: { "Content-Type": "application/json", "X-VoidMetric-Engine": "v3.0-Blind-Spectral-Padded" } }
    );
    
  } catch (error) {
    console.error("Compute Execution Pipeline Failure:", error);
    return new Response(JSON.stringify({ error: "Malformed streaming metric payload." }), { status: 400 });
  }
};   