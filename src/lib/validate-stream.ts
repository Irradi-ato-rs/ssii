// src/lib/validate-stream.ts
// Shared stream validation + normalization. Imported by both the void
// worker and large-ingest-consumer. Single source of truth for the
// N×12 padded stream contract.

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
    this.cause = 'validation';
  }
}

export interface PaddedStreamNode {
  maskedValue: number;
  lastTelemetryHeartbeat: number;
  row: number;
  col: number;
}

export function buildPaddedStream(
  rawPayload: any,
  blockCount: number,
  timestamp: number
): PaddedStreamNode[] | PaddedStreamNode[][] {
  if (rawPayload.blocks && Array.isArray(rawPayload.blocks)) {
    if (rawPayload.blocks.length !== blockCount) {
      throw new ValidationError(
        `Block count mismatch: expected ${blockCount}, received ${rawPayload.blocks.length}`
      );
    }
    for (let b = 0; b < blockCount; b++) {
      const block = rawPayload.blocks[b];
      if (!Array.isArray(block) || block.length !== 12) {
        throw new ValidationError(`Block ${b}: expected 12 nodes, received ${block?.length ?? 0}`);
      }
      const seen: Set<string> = new Set();
      for (const node of block) {
        if (typeof node.row !== 'number' || node.row < 0 || node.row > 3) {
          throw new ValidationError(`Block ${b}: invalid row ${node.row}`);
        }
        if (typeof node.col !== 'number' || node.col < 0 || node.col > 2) {
          throw new ValidationError(`Block ${b}: invalid col ${node.col}`);
        }
        if (typeof node.maskedValue !== 'number' || node.maskedValue < 0 || node.maskedValue > 1) {
          throw new ValidationError(`Block ${b}: maskedValue out of [0,1] range: ${node.maskedValue}`);
        }
        const key = `${node.row}:${node.col}`;
        if (seen.has(key)) {
          throw new ValidationError(`Block ${b}: duplicate cell (${node.row}, ${node.col})`);
        }
        seen.add(key);
      }
    }
    return rawPayload.blocks;
  }

  const baseValue = typeof rawPayload.value === 'number' ? rawPayload.value : 0.2;
  const blocks: PaddedStreamNode[][] = [];
  for (let b = 0; b < blockCount; b++) {
    const block: PaddedStreamNode[] = [];
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 3; j++) {
        block.push({
          maskedValue: baseValue,
          row: i,
          col: j,
          lastTelemetryHeartbeat: timestamp,
        });
      }
    }
    blocks.push(block);
  }
  return blockCount === 1 ? blocks[0] : blocks;
}