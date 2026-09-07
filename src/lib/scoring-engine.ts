// src/lib/scoring-engine.ts
// Pure computation, no request/response/auth concerns — this file is
// designed to be liftable, unchanged, into a separate authoritative
// Worker if/when that becomes necessary.
//
// Hyperparameters are injected per-tenant from the private void worker.
// Defaults below match the open-core baseline.

const TOL = 1e-6;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PaddedStreamNode {
  maskedValue: number;
  lastTelemetryHeartbeat: number;
  row: number; // 0..3
  col: number; // 0..2
}

export interface EngineParams {
  priorityAlpha: [number, number, number, number];
  baseEnablerWeights: [number, number, number];
  decayRate: number;
  /** Deterministic aging spread coefficient (√dt scaling). */
  driftVolatility: number;
  sigmoidSteepness: number;
  sigmoidMidpoint: number;
  chaosScale: number;
  statusThreshold: number;
  resonanceThreshold: number;
  /** Breaker trips when any sigmoid-output C_{i,j} falls below this. */
  breakerThreshold: number;
  breakerFloor: number;
  /** Numerical floor preventing ln(0) in the row-validation log-sum. */
  siLiveFloor: number;
  /** Trend classification threshold (SI_Live delta between early/late thirds). */
  trendThreshold: number;
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
  trendThreshold: 0.02,
};

export const STATUS = {
  NOMINAL: 'NOMINAL',
  CRITICAL_RISK_SWITCH_TRIGGERED: 'CRITICAL_RISK_SWITCH_TRIGGERED',
} as const;

export type Status = typeof STATUS[keyof typeof STATUS];

export type Trend = 'improving' | 'degrading' | 'stable';

export interface SpectralAnalysis {
  chaosIndexPenalty: number;
  principalEigenvalue: number;
  resonanceExploitChainDetected: boolean;
}

export interface TemporalAnalysis {
  blockCount: number;
  /** Index of first block where SI_Live < statusThreshold, or -1 if never. */
  onsetBlock: number;
  persistence: number;
  trend: Trend;
  siLiveSeries: number[];
  metricASeries: number[];
  /** Indices (into the input blocks array) where the breaker tripped. */
  breakerBlocks: number[];
}

export interface ScoringResult {
  metricACompliance: number;
  metricAVelocity: number | null;
  metricBIntegrity: number;
  status: Status;
  watermelonIndex: number;
  honestFailureIndex: number;
  rowValidations: [number, number, number, number];
  spectralAnalysis: SpectralAnalysis;
  temporal: TemporalAnalysis | null;
  alphaVector: [number, number, number, number];
  threatIntelStale: boolean;
  threatVectorAnomaly: boolean;
}

// ─── Internal: single-block computation ──────────────────────────────────────

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
  baseWeights: [number, number, number],
  alpha: [number, number, number, number],
  p: EngineParams,
  now: number,
  hasEverReported?: boolean[][]
): BlockComputation {
  const matrix: number[][] = Array.from({ length: 4 }, () => [0, 0, 0]);
  let scoreA = 0;
  let breakerTripped = false;

  for (const node of block) {
    const i = node.row;
    const j = node.col;
    if (i < 0 || i > 3 || j < 0 || j > 2) continue;

    const dt = Math.max(0, now - node.lastTelemetryHeartbeat) / 3600;
    const drifted = Math.max(p.siLiveFloor, Math.min(1.0,
      node.maskedValue - p.decayRate * dt - p.driftVolatility * Math.sqrt(dt)
    ));
    const sigmoidal = 1 / (1 + Math.exp(-p.sigmoidSteepness * (drifted - p.sigmoidMidpoint)));

    matrix[i][j] = sigmoidal;
    scoreA += sigmoidal * baseWeights[j] * alpha[i];

    if (sigmoidal < p.breakerThreshold) {
      breakerTripped = true;
    }
  }

  // Per-row weighted geometric mean (exclude never-reported cells)
  const rowValidations: number[] = [];
  for (let i = 0; i < 4; i++) {
    const activeCols = [0, 1, 2].filter(j => !hasEverReported || hasEverReported[i][j]);
    if (activeCols.length === 0) {
      rowValidations.push(1.0);
      continue;
    }
    const weightSum = activeCols.reduce((s, j) => s + baseWeights[j], 0);
    const logSum = activeCols.reduce((s, j) =>
      s + (baseWeights[j] / weightSum) * Math.log(Math.max(matrix[i][j], p.siLiveFloor)), 0);
    rowValidations.push(Math.exp(logSum));
  }

  // Weighted harmonic mean across rows
  let harmonicDenom = 0;
  for (let i = 0; i < 4; i++) {
    harmonicDenom += alpha[i] / (rowValidations[i] + TOL);
  }
  const rawSiLive = 1.0 / (harmonicDenom + TOL);

  // Deficit Gram matrix (4×4) — symmetric PSD by construction
  const gram: number[][] = Array.from({ length: 4 }, () => [0, 0, 0, 0]);
  for (let i = 0; i < 4; i++) {
    for (let q = i; q < 4; q++) {
      let dot = 0;
      for (let j = 0; j < 3; j++) {
        dot += (1 - matrix[i][j]) * (1 - matrix[q][j]);
      }
      gram[i][q] = dot;
      gram[q][i] = dot;
    }
  }

  // Power iteration for λ_max (32 iterations, sufficient for 4×4)
  let eigVec = [1.0, 1.0, 1.0, 1.0];
  let principalEigenvalue = 0;
  for (let iter = 0; iter < 32; iter++) {
    const next = [0, 0, 0, 0];
    for (let i = 0; i < 4; i++) {
      for (let q = 0; q < 4; q++) {
        next[i] += gram[i][q] * eigVec[q];
      }
    }
    const norm = Math.sqrt(next.reduce((s, v) => s + v * v, 0));
    if (norm < TOL) break;
    principalEigenvalue = norm;
    eigVec = next.map(v => v / norm);
  }

  const trace = gram[0][0] + gram[1][1] + gram[2][2] + gram[3][3];
  const chaosPenalty = Math.max(0, (principalEigenvalue - trace / 4) * p.chaosScale);

  let metricB = Math.max(p.siLiveFloor, rawSiLive - chaosPenalty);
  if (breakerTripped) {
    metricB = Math.min(metricB, p.breakerFloor);
  }

  const spectral: SpectralAnalysis = {
    chaosIndexPenalty: chaosPenalty,
    principalEigenvalue,
    resonanceExploitChainDetected: chaosPenalty > p.resonanceThreshold,
  };

  return { metricA: scoreA, metricB, rowValidations, spectral, breakerTripped, sigmoidalMatrix: matrix };
}

// ─── Internal: Laspeyres velocity on raw values ──────────────────────────────

function computeLevelRaw(
  block: PaddedStreamNode[],
  weights: [number, number, number],
  alpha: [number, number, number, number]
): number {
  let acc = 0;
  for (const node of block) {
    if (node.row < 0 || node.row > 3 || node.col < 0 || node.col > 2) continue;
    acc += node.maskedValue * weights[node.col] * alpha[node.row];
  }
  return acc;
}

// ─── Internal: normalize weights with threat vector ──────────────────────────

function normalizeWeights(
  base: [number, number, number],
  threatIntel: number[]
): [number, number, number] {
  const dynamic = base.map((w, j) => w * (1 + 1.8 * (threatIntel[j] || 0)));
  const sum = dynamic[0] + dynamic[1] + dynamic[2];
  if (sum < TOL) return [1 / 3, 1 / 3, 1 / 3];
  return [dynamic[0] / sum, dynamic[1] / sum, dynamic[2] / sum];
}

// ─── Internal: threat vector anomaly ─────────────────────────────────────────

function computeThreatVectorAnomaly(
  current: number[],
  previous: number[] | null,
  base: [number, number, number]
): boolean {
  if (!previous) return false;
  for (let j = 0; j < 3; j++) {
    const wCurr = base[j] * (1 + 1.8 * current[j]);
    const wPrev = base[j] * (1 + 1.8 * previous[j]);
    if (Math.abs(wPrev) < TOL) continue;
    if (Math.abs(wCurr - wPrev) / Math.abs(wPrev) > 0.3) return true;
  }
  return false;
}

// ─── Internal: round to 4 decimal places ─────────────────────────────────────

function r4(x: number): number {
  return Number(x.toFixed(4));
}

// ─── Public entry point ──────────────────────────────────────────────────────

/**
 * Compute the scoring result.
 *
 * @param now - Current time in epoch seconds. The function is deterministic
 *   given the same `now`.
 * @param paddedStream - 12 nodes (4 rows × 3 cols) for N=1, or an array of
 *   blocks for N>1.
 * @param threatIntel - Threat-intelligence vector, each value ∈ [0,1].
 * @param previousStream - Previous block(s) for Laspeyres velocity.
 * @param previousThreatIntel - Previous threat vector (falls back to current
 *   if not provided).
 * @param params - Parameter overrides. Merged over defaults.
 * @param hasEverReported - Per-cell activity flag [4][3]. `undefined` = all active.
 */
export function runScoringEngine(
  now: number,
  paddedStream: PaddedStreamNode[] | PaddedStreamNode[][],
  threatIntel: number[],
  previousStream?: PaddedStreamNode[] | PaddedStreamNode[][],
  previousThreatIntel?: number[],
  params?: Partial<EngineParams>,
  hasEverReported?: boolean[][]
): ScoringResult {
  const p: EngineParams = { ...DEFAULT_PARAMS, ...params };

  // Detect N
  const blocks: PaddedStreamNode[][] = Array.isArray(paddedStream[0])
    ? paddedStream as PaddedStreamNode[][]
    : [paddedStream as PaddedStreamNode[]];

  const N = blocks.length;
  const currentBlock = blocks[N - 1];
  const baseWeights = normalizeWeights(p.baseEnablerWeights, threatIntel);

  const perBlock: BlockComputation[] = blocks.map((block) =>
    computeSingleBlock(block, baseWeights, p.priorityAlpha, p, now, hasEverReported)
  );

  const last = perBlock[N - 1];

  // Velocity: Laspeyres (frozen at previous weights)
  let velocity: number | null = null;
  if (previousStream) {
    const prevBlocks: PaddedStreamNode[][] = Array.isArray(previousStream[0])
      ? previousStream as PaddedStreamNode[][]
      : [previousStream as PaddedStreamNode[]];
    const prevBlock = prevBlocks[prevBlocks.length - 1];
    const prevIntel = previousThreatIntel ?? threatIntel;
    const prevWeights = normalizeWeights(p.baseEnablerWeights, prevIntel);
    const currentAtPrev = computeLevelRaw(currentBlock, prevWeights, p.priorityAlpha);
    const prevAtPrev = computeLevelRaw(prevBlock, prevWeights, p.priorityAlpha);
    velocity = r4(currentAtPrev - prevAtPrev);
  }

  // Round metricA and metricB first, then derive WI and HF from rounded values
  const metricAr = r4(last.metricA);
  const metricBr = r4(last.metricB);
  const wiR = r4(metricAr * (1 - metricBr));
  const hfR = r4((1 - metricAr) * (1 - metricBr));

  // Tiling identity: WI + HF = 1 − SI_Live (holds to within ~5e-5 after rounding)
  if (Math.abs(wiR + hfR - (1 - metricBr)) > 1e-4) {
    // In a library, this should be a debug assertion, not a console call.
    // Omit entirely in production builds.
  }

  // Temporal analysis (N > 1)
  let temporal: TemporalAnalysis | null = null;
  if (N > 1) {
    const siLiveSeries = perBlock.map(b => b.metricB);
    const metricASeries = perBlock.map(b => b.metricA);
    const breakerBlocks: number[] = [];
    perBlock.forEach((b, idx) => { if (b.breakerTripped) breakerBlocks.push(idx); });

    // Onset: first block index where SI_Live < statusThreshold, or -1 if never
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
    const trend: Trend =
      trendDelta > p.trendThreshold ? 'improving'
      : trendDelta < -p.trendThreshold ? 'degrading'
      : 'stable';

    temporal = {
      blockCount: N,
      onsetBlock,
      persistence,
      trend,
      siLiveSeries,
      metricASeries,
      breakerBlocks,
    };
  }

  return {
    metricACompliance: metricAr,
    metricAVelocity: velocity,
    metricBIntegrity: metricBr,
    status: last.metricB < p.statusThreshold
      ? STATUS.CRITICAL_RISK_SWITCH_TRIGGERED
      : STATUS.NOMINAL,
    watermelonIndex: wiR,
    honestFailureIndex: hfR,
    rowValidations: last.rowValidations.map(r4) as [number, number, number, number],
    spectralAnalysis: last.spectral,
    temporal,
    alphaVector: p.priorityAlpha,
    threatIntelStale: threatIntel.every(t => t === 0),
    threatVectorAnomaly: computeThreatVectorAnomaly(
      threatIntel,
      previousThreatIntel ?? null,
      p.baseEnablerWeights
    ),
  };
}   