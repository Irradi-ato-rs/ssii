// Copyright (c) 2026 Irradi.ato.rs/VoidMetric
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.   
//
// src/lib/scoring-engine.ts
// Pure computation, no request/response/auth concerns — this file is
// designed to be liftable, unchanged, into a separate authoritative
// Worker if/when that becomes necessary.
//
// Hyperparameters are injected per-tenant from the private void worker.
// Defaults below match the open-core baseline.

export interface PaddedStreamNode {
  maskedValue: number;
  lastTelemetryHeartbeat: number;
  row: number;   // 0..3
  col: number;   // 0..2
}

export interface EngineParams {
  priorityAlpha: number[];          // [0.50, 0.30, 0.15, 0.05]
  baseEnablerWeights: number[];     // [0.4, 0.3, 0.3]
  decayRate: number;                // 0.005
  driftVolatility: number;          // 0.04
  sigmoidSteepness: number;         // 10.0
  sigmoidMidpoint: number;          // 0.5
  chaosScale: number;               // 0.25 (κ)
  statusThreshold: number;          // 0.20
  resonanceThreshold: number;       // 0.15
  breakerThreshold: number;         // 0.05
  breakerFloor: number;             // 0.015
  siLiveFloor: number;              // 0.0001
}

export const DEFAULT_PARAMS: EngineParams = {
  priorityAlpha: [0.50, 0.30, 0.15, 0.05],
  baseEnablerWeights: [0.4, 0.3, 0.3],
  decayRate: 0.005,
  driftVolatility: 0.04,
  sigmoidSteepness: 10.0,
  sigmoidMidpoint: 0.5,
  chaosScale: 0.25,
  statusThreshold: 0.20,
  resonanceThreshold: 0.15,
  breakerThreshold: 0.05,
  breakerFloor: 0.015,
  siLiveFloor: 0.0001,
};

export interface SpectralAnalysis {
  chaos_index_penalty: number;
  principal_eigenvalue: number;
  resonance_exploit_chain_detected: boolean;
}

export interface TemporalAnalysis {
  block_count: number;
  onset_block: number;
  persistence: number;
  trend: 'improving' | 'degrading' | 'stable';
  si_live_series: number[];
  metric_a_series: number[];
  breaker_blocks: number[];
}

export interface ScoringResult {
  metric_a_compliance: number;
  metric_a_velocity: number | null;
  metric_b_integrity: number;
  status: string;
  watermelon_index: number;
  honest_failure_index: number;
  row_validations: number[];
  spectral_analysis: SpectralAnalysis;
  temporal?: TemporalAnalysis;
}

const EPSILON = 1e-6;

// ─── Internal: single-block computation ─────────────────────────────────────

interface BlockComputation {
  metricA: number;
  metricB: number;
  rowValidations: number[];
  spectral: SpectralAnalysis;
  breakerTripped: boolean;
  sigmoidalMatrix: number[][];
}

function computeSingleBlock(
  block: PaddedStreamNode[],
  normalizedWeights: number[],
  alpha: number[],
  p: EngineParams,
  now: number
): BlockComputation {
  const reconstructedSigmoidalMatrix: number[][] =
    Array(4).fill(0).map(() => Array(3).fill(0.0));

  let scoreA = 0;
  let breakerTripped = false;

  block.forEach((node) => {
    const i = node.row;
    const j = node.col;
    if (i < 0 || i > 3 || j < 0 || j > 2) return;

    const dt = Math.max(0, (now - node.lastTelemetryHeartbeat) / 3600);
    const expectedDecay = node.maskedValue - (p.decayRate * dt) - (p.driftVolatility * Math.sqrt(dt));
    const driftedScore = Math.max(p.siLiveFloor, Math.min(1.0, expectedDecay));
    const sigmoidalScore = 1 / (1 + Math.exp(-p.sigmoidSteepness * (driftedScore - p.sigmoidMidpoint)));

    reconstructedSigmoidalMatrix[i][j] = sigmoidalScore;
    scoreA += sigmoidalScore * normalizedWeights[j] * alpha[i];

    if (sigmoidalScore < p.breakerThreshold) {
      breakerTripped = true;
    }
  });

  // Per-row geometric product
  const rowValidations: number[] = reconstructedSigmoidalMatrix.map((row) => {
    let rowLogSum = 0;
    for (let j = 0; j < 3; j++) {
      rowLogSum += normalizedWeights[j] * Math.log(row[j] || p.siLiveFloor);
    }
    return Math.exp(rowLogSum);
  });

  // Harmonic aggregation
  let harmonicDenominator = 0;
  for (let i = 0; i < 4; i++) {
    harmonicDenominator += alpha[i] / (rowValidations[i] + EPSILON);
  }
  const rawSiLive = 1.0 / (harmonicDenominator + EPSILON);

  // Deficit Gram matrix
  const covariance: number[][] = Array(4).fill(0).map(() => Array(4).fill(0));
  for (let i = 0; i < 4; i++) {
    for (let q = 0; q < 4; q++) {
      let dotProduct = 0;
      for (let j = 0; j < 3; j++) {
        dotProduct += (1 - reconstructedSigmoidalMatrix[i][j]) * (1 - reconstructedSigmoidalMatrix[q][j]);
      }
      covariance[i][q] = dotProduct;
    }
  }

  // Power iteration for λ_max
  let eigenVector = [1.0, 1.0, 1.0, 1.0];
  let principalEigenvalue = 0;
  for (let iter = 0; iter < 8; iter++) {
    const nextVector = [0.0, 0.0, 0.0, 0.0];
    for (let i = 0; i < 4; i++) {
      for (let q = 0; q < 4; q++) {
        nextVector[i] += covariance[i][q] * eigenVector[q];
      }
    }
    const norm = Math.sqrt(nextVector.reduce((sum, v) => sum + v * v, 0));
    principalEigenvalue = norm;
    eigenVector = nextVector.map(v => v / (norm || 1));
  }

  const trace = covariance[0][0] + covariance[1][1] + covariance[2][2] + covariance[3][3];
  const chaosPenalty = Math.max(0, (principalEigenvalue - (trace / 4)) * p.chaosScale);

  let metricB = Math.max(p.siLiveFloor, rawSiLive - chaosPenalty);
  if (breakerTripped) {
    metricB = Math.min(metricB, p.breakerFloor);
  }

  const spectral: SpectralAnalysis = {
    chaos_index_penalty: Number(chaosPenalty.toFixed(5)),
    principal_eigenvalue: Number(principalEigenvalue.toFixed(5)),
    resonance_exploit_chain_detected: chaosPenalty > p.resonanceThreshold,
  };

  return { metricA: scoreA, metricB, rowValidations, spectral, breakerTripped, sigmoidalMatrix: reconstructedSigmoidalMatrix };
}

// ─── Internal: Laspeyres velocity on raw values ─────────────────────────────

function computeLevelRaw(block: PaddedStreamNode[], normalizedWeights: number[], alpha: number[]): number {
  let acc = 0;
  for (const node of block) {
    if (node.row < 0 || node.row > 3 || node.col < 0 || node.col > 2) continue;
    acc += node.maskedValue * normalizedWeights[node.col] * alpha[node.row];
  }
  return acc;
}

// ─── Internal: normalize weights with threat vector ─────────────────────────

function normalizeWeights(base: number[], threatIntel: number[]): number[] {
  const dynamic = base.map((w, j) => w * (1 + 1.8 * (threatIntel[j] || 0)));
  const sum = dynamic.reduce((a, b) => a + b, 0);
  return dynamic.map(w => w / (sum || 1));
}

// ─── Public entry point ─────────────────────────────────────────────────────

export function runScoringEngine(
  paddedStream: PaddedStreamNode[] | PaddedStreamNode[][],
  threatIntel: number[],
  previousStream?: PaddedStreamNode[] | PaddedStreamNode[][],
  previousThreatIntel?: number[],
  params?: Partial<EngineParams>
): ScoringResult {
  const p = { ...DEFAULT_PARAMS, ...params };
  const now = Math.floor(Date.now() / 1000);

  // Detect N
  const blocks: PaddedStreamNode[][] = Array.isArray(paddedStream[0])
    ? (paddedStream as PaddedStreamNode[][])
    : [paddedStream as PaddedStreamNode[]];

  const N = blocks.length;
  const currentBlock = blocks[N - 1];
  const normalizedWeights = normalizeWeights(p.baseEnablerWeights, threatIntel);

  // ─── N=1: existing path (unchanged semantics) ─────────────────────────────
  if (N === 1) {
    const comp = computeSingleBlock(currentBlock, normalizedWeights, p.priorityAlpha, p, now);

    let velocity: number | null = null;
    if (previousStream && Array.isArray(previousStream[0]) === false) {
      const prevBlock = previousStream as PaddedStreamNode[];
      const prevIntel = previousThreatIntel || [0, 0, 0];
      const prevWeights = normalizeWeights(p.baseEnablerWeights, prevIntel);
      const currentAtPrev = computeLevelRaw(currentBlock, prevWeights, p.priorityAlpha);
      const prevAtPrev = computeLevelRaw(prevBlock, prevWeights, p.priorityAlpha);
      velocity = Number((currentAtPrev - prevAtPrev).toFixed(4));
    }

    const wi = comp.metricA * (1 - comp.metricB);
    const hf = (1 - comp.metricA) * (1 - comp.metricB);

    const identityResidual = Math.abs(wi + hf - (1 - comp.metricB));
    if (identityResidual > EPSILON) {
      console.warn(
        `Identity 1 violated: WI+HF=${(wi + hf).toFixed(6)} vs 1-SI_Live=${(1 - comp.metricB).toFixed(6)} (residual=${identityResidual.toExponential(2)})`
      );
    }

    return {
      metric_a_compliance: Number(comp.metricA.toFixed(4)),
      metric_a_velocity: velocity,
      metric_b_integrity: Number(comp.metricB.toFixed(4)),
      status: comp.metricB < p.statusThreshold ? "CRITICAL_RISK_SWITCH_TRIGGERED" : "NOMINAL",
      watermelon_index: Number(wi.toFixed(4)),
      honest_failure_index: Number(hf.toFixed(4)),
      row_validations: comp.rowValidations.map(v => Number(v.toFixed(4))),
      spectral_analysis: comp.spectral,
    };
  }

  // ─── N>1: per-block compute + temporal aggregation ─────────────────────────

  const perBlock: BlockComputation[] = blocks.map((block) =>
    computeSingleBlock(block, normalizedWeights, p.priorityAlpha, p, now)
  );

  // Primary score = last block
  const last = perBlock[N - 1];

  // Velocity: Laspeyres between last and second-to-last block (within-message)
  let velocity: number | null = null;
  if (N >= 2) {
    const prevBlock = blocks[N - 2];
    const prevIntel = previousThreatIntel || threatIntel;
    const prevWeights = normalizeWeights(p.baseEnablerWeights, prevIntel);
    const currentAtPrev = computeLevelRaw(currentBlock, prevWeights, p.priorityAlpha);
    const prevAtPrev = computeLevelRaw(prevBlock, prevWeights, p.priorityAlpha);
    velocity = Number((currentAtPrev - prevAtPrev).toFixed(4));
  }

  // Temporal analysis
  const siLiveSeries = perBlock.map(b => b.metricB);
  const metricASeries = perBlock.map(b => b.metricA);
  const breakerBlocks: number[] = [];
  perBlock.forEach((b, idx) => { if (b.breakerTripped) breakerBlocks.push(idx); });

  // Onset: first block index where SI_Live < statusThreshold
  let onsetBlock = -1;
  for (let i = 0; i < N; i++) {
    if (siLiveSeries[i] < p.statusThreshold) {
      onsetBlock = i;
      break;
    }
  }

  // Persistence: consecutive blocks at the end where SI_Live < statusThreshold
  let persistence = 0;
  for (let i = N - 1; i >= 0; i--) {
    if (siLiveSeries[i] < p.statusThreshold) {
      persistence++;
    } else {
      break;
    }
  }

  // Trend: compare first third to last third of SI_Live series
  const third = Math.max(1, Math.floor(N / 3));
  const earlyMean = siLiveSeries.slice(0, third).reduce((a, b) => a + b, 0) / third;
  const lateMean = siLiveSeries.slice(-third).reduce((a, b) => a + b, 0) / third;
  const trendDelta = lateMean - earlyMean;
  const trend: 'improving' | 'degrading' | 'stable' =
    trendDelta > 0.02 ? 'improving' : trendDelta < -0.02 ? 'degrading' : 'stable';

  const wi = last.metricA * (1 - last.metricB);
  const hf = (1 - last.metricA) * (1 - last.metricB);

  const identityResidual = Math.abs(wi + hf - (1 - last.metricB));
  if (identityResidual > EPSILON) {
    console.warn(
      `Identity 1 violated: WI+HF=${(wi + hf).toFixed(6)} vs 1-SI_Live=${(1 - last.metricB).toFixed(6)} (residual=${identityResidual.toExponential(2)})`
    );
  }

  return {
    metric_a_compliance: Number(last.metricA.toFixed(4)),
    metric_a_velocity: velocity,
    metric_b_integrity: Number(last.metricB.toFixed(4)),
    status: last.metricB < p.statusThreshold ? "CRITICAL_RISK_SWITCH_TRIGGERED" : "NOMINAL",
    watermelon_index: Number(wi.toFixed(4)),
    honest_failure_index: Number(hf.toFixed(4)),
    row_validations: last.rowValidations.map(v => Number(v.toFixed(4))),
    spectral_analysis: last.spectral,
    temporal: {
      block_count: N,
      onset_block: onsetBlock,
      persistence,
      trend,
      si_live_series: siLiveSeries.map(v => Number(v.toFixed(4))),
      metric_a_series: metricASeries.map(v => Number(v.toFixed(4))),
      breaker_blocks: breakerBlocks,
    },
  };
}