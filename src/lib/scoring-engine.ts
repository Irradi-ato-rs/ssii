// src/lib/scoring-engine.ts
// Pure computation, no request/response/auth concerns — this file is
// designed to be liftable, unchanged, into a separate authoritative
// Worker if/when that becomes necessary (see architecture notes on
// Option A vs Option B provenance enforcement).

export interface PaddedStreamNode {
  maskedValue: number;
  lastTelemetryHeartbeat: number;
  row: number;   // 0..3
  col: number;   // 0..2
}

export interface ScoringResult {
  metric_a_compliance: number;
  metric_a_velocity: number | null;  // null if previous frame unavailable
  metric_b_integrity: number;
  status: string;
  watermelon_index: number;
  honest_failure_index: number;
  row_validations: number[];
  spectral_analysis: {
    chaos_index_penalty: number;
    principal_eigenvalue: number;
    resonance_exploit_chain_detected: boolean;
  };
}

const PRIORITY_ALPHA = [0.50, 0.30, 0.15, 0.05];
const BASE_ENABLER_WEIGHTS = [0.4, 0.3, 0.3];
const EPSILON = 1e-6;
const S_CURVE_STEEPNESS = 10.0;
const S_CURVE_MIDPOINT = 0.5;

// --- Tuning constants ---
const CHAOS_SCALE = 0.25;
const STATUS_THRESHOLD = 0.20;
const RESONANCE_THRESHOLD = 0.15;
const BREAKER_FLOOR = 0.015;
const BREAKER_THRESHOLD = 0.05;
const SI_LIVE_FLOOR = 0.0001;

function computeLevel(paddedStream: PaddedStreamNode[], normalizedWeights: number[]): number {
  let acc = 0;
  for (const node of paddedStream) {
    if (node.row < 0 || node.row > 3 || node.col < 0 || node.col > 2) continue;
    const w = normalizedWeights[node.col];
    const alpha = PRIORITY_ALPHA[node.row];
    acc += node.maskedValue * w * alpha;
  }
  return acc;
}

export function runScoringEngine(
  paddedStream: PaddedStreamNode[],
  threatIntel: number[],
  previousStream?: PaddedStreamNode[],
  previousThreatIntel?: number[]
): ScoringResult {
  const now = Math.floor(Date.now() / 1000);

  // --- Dynamic weight reallocation (current cycle) ---
  const dynamicWeights = BASE_ENABLER_WEIGHTS.map((w, j) => w * (1 + 1.8 * (threatIntel[j] || 0)));
  const weightSum = dynamicWeights.reduce((a, b) => a + b, 0);
  const normalizedWeights = dynamicWeights.map(w => w / (weightSum || 1));

  // --- Matrix with temporal decay + sigmoid ---
  const reconstructedSigmoidalMatrix: number[][] = Array(4).fill(0).map(() => Array(3).fill(0.0));

  let scoreA_Accumulator = 0;
  let criticalBreakerTripped = false;

  paddedStream.forEach((node) => {
    const i_row = node.row;
    const j_col = node.col;
    if (i_row < 0 || i_row > 3 || j_col < 0 || j_col > 2) return;

    const activeWeight = normalizedWeights[j_col];
    const activePriority = PRIORITY_ALPHA[i_row];

    const dt = Math.max(0, (now - node.lastTelemetryHeartbeat) / 3600);
    const driftVolatility = 0.04;
    const expectedDecay = node.maskedValue - (0.005 * dt) - (driftVolatility * Math.sqrt(dt));
    const driftedScore = Math.max(0.0001, Math.min(1.0, expectedDecay));
    const sigmoidalScore = 1 / (1 + Math.exp(-S_CURVE_STEEPNESS * (driftedScore - S_CURVE_MIDPOINT)));

    reconstructedSigmoidalMatrix[i_row][j_col] = sigmoidalScore;
    scoreA_Accumulator += sigmoidalScore * activeWeight * activePriority;

    if (sigmoidalScore < BREAKER_THRESHOLD) {
      criticalBreakerTripped = true;
    }
  });

  // --- Metric A Velocity (frozen-weight delta) ---
  // Both terms use the PREVIOUS cycle's weights, isolating compliance drift
  // from threat-vector reallocation.
  let metricA_Velocity: number | null = null;
  if (previousStream && previousStream.length === 12) {
    const prevWeights = BASE_ENABLER_WEIGHTS.map((w, j) => w * (1 + 1.8 * ((previousThreatIntel || [0,0,0])[j] || 0)));
    const prevWeightSum = prevWeights.reduce((a, b) => a + b, 0);
    const prevNormalizedWeights = prevWeights.map(w => w / (prevWeightSum || 1));

    // Score_A at current time, previous weights
    const currentAtPrevWeights = computeLevel(paddedStream, prevNormalizedWeights);
    // Score_A at previous time, previous weights
    const prevAtPrevWeights = computeLevel(previousStream, prevNormalizedWeights);

    metricA_Velocity = Number((currentAtPrevWeights - prevAtPrevWeights).toFixed(4));
  }

  // --- Deficit Gram matrix ---
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

  // --- Power iteration for λ_max ---
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
  const chaosIndexPenalty = Math.max(0, (principalEigenvalue - (trace / 4)) * CHAOS_SCALE);

  // --- Metric A final ---
  const finalScoreA = scoreA_Accumulator;

  // --- Metric B: geometric product per row, harmonic mean across rows ---
  const finalRowValidations = reconstructedSigmoidalMatrix.map((row) => {
    let rowLogSum = 0;
    for (let j = 0; j < 3; j++) {
      rowLogSum += normalizedWeights[j] * Math.log(row[j] || 0.0001);
    }
    return Math.exp(rowLogSum);
  });

  let harmonicDenominator = 0;
  for (let i = 0; i < 4; i++) {
    harmonicDenominator += PRIORITY_ALPHA[i] / (finalRowValidations[i] + EPSILON);
  }

  const rawSiLiveHarmonic = 1.0 / (harmonicDenominator + EPSILON);
  let finalScoreB = Math.max(SI_LIVE_FLOOR, rawSiLiveHarmonic - chaosIndexPenalty);

  if (criticalBreakerTripped) {
    finalScoreB = Math.min(finalScoreB, BREAKER_FLOOR);
  }

  // --- Diagnostics ---
  const wi = finalScoreA * (1 - finalScoreB);
  const hf = (1 - finalScoreA) * (1 - finalScoreB);

  const identityResidual = Math.abs(wi + hf - (1 - finalScoreB));
  if (identityResidual > EPSILON) {
    console.warn(
      `Identity 1 violated: WI+HF=${(wi + hf).toFixed(6)} vs 1-SI_Live=${(1 - finalScoreB).toFixed(6)} (residual=${identityResidual.toExponential(2)})`
    );
  }

  return {
    metric_a_compliance: Number(finalScoreA.toFixed(4)),
    metric_a_velocity: metricA_Velocity,
    metric_b_integrity: Number(finalScoreB.toFixed(4)),
    status: finalScoreB < STATUS_THRESHOLD ? "CRITICAL_RISK_SWITCH_TRIGGERED" : "NOMINAL",
    watermelon_index: Number(wi.toFixed(4)),
    honest_failure_index: Number(hf.toFixed(4)),
    row_validations: finalRowValidations.map(v => Number(v.toFixed(4))),
    spectral_analysis: {
      chaos_index_penalty: Number(chaosIndexPenalty.toFixed(5)),
      principal_eigenvalue: Number(principalEigenvalue.toFixed(5)),
      resonance_exploit_chain_detected: chaosIndexPenalty > RESONANCE_THRESHOLD,
    },
  };
}   