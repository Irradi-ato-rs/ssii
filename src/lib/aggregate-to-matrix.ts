// src/lib/aggregate-to-matrix.ts
// Platform-agnostic aggregation: takes a batch of CanonicalEvents and
// produces a PaddedStreamNode[12] ready for the scoring engine.
// One implementation. No platform-specific code.

import type { CanonicalEvent, Category } from './canonical-event';
import type { PaddedStreamNode } from './scoring-engine';

const CATEGORY_TO_ROW: Record<Category, number> = {
  identity: 1, access: 1, admin: 1,
  policy: 0, governance: 0, compliance: 0,
  physical: 2, facilities: 2,
  vulnerability: 3, network: 3, endpoint: 3, cloud: 3, data: 3,
};

const STATUS_TO_BASE: Record<string, number> = {
  success: 0.9,
  resolved: 0.85,
  suppressed: 0.5,
  detected: 0.4,
  failure: 0.2,
  open: 0.1,
};

function computeMaskedValue(event: CanonicalEvent): number {
  const base = STATUS_TO_BASE[event.status] ?? 0.5;
  const adjustment = (event.severity - 0.5) * 0.4;
  const isNegative = event.status === 'open' || event.status === 'failure';
  const value = isNegative
    ? base - Math.abs(adjustment)
    : base + Math.abs(adjustment);
  return Math.max(0.01, Math.min(1.0, value));
}

function detectColumn(event: CanonicalEvent): number {
  if (event.status === 'resolved' || event.status === 'suppressed') return 1;
  if (event.severity > 0.7 && (event.status === 'open' || event.status === 'failure')) return 2;
  return 0;
}

export function aggregateToMatrix(events: CanonicalEvent[], now: number): PaddedStreamNode[] {
  const sums: number[][] = Array(4).fill(0).map(() => Array(3).fill(0));
  const counts: number[][] = Array(4).fill(0).map(() => Array(3).fill(0));
  const lastSeen: number[][] = Array(4).fill(0).map(() => Array(3).fill(0));

  for (const event of events) {
    const row = CATEGORY_TO_ROW[event.category] ?? 3;
    const col = detectColumn(event);
    const value = computeMaskedValue(event);

    sums[row][col] += value;
    counts[row][col]++;
    lastSeen[row][col] = Math.max(lastSeen[row][col], event.timestamp);
  }

  const nodes: PaddedStreamNode[] = [];
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 3; j++) {
      nodes.push({
        maskedValue: counts[i][j] > 0 ? sums[i][j] / counts[i][j] : 0.5,
        row: i,
        col: j,
        lastTelemetryHeartbeat: lastSeen[i][j] || now,
      });
    }
  }
  return nodes;
}