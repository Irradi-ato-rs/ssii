// src/lib/index.ts
// @voidmetric/core — barrel export
// import { runScoringEngine, aggregateToMatrix, normalizeWithConfig } from '@voidmetric/core';

export type { CanonicalEvent, Category, Status } from './canonical-event';
export { ALL_CATEGORIES, ALL_STATUSES } from './canonical-event';
export type { AdapterConfig } from './adapter-config';
export { validateAdapterConfig } from './adapter-config';
export { normalizeWithConfig } from './normalize-with-config';
export type { AggregationResult } from './aggregate-to-matrix';
export { aggregateToMatrix } from './aggregate-to-matrix';
export type { PaddedStreamNode, EngineParams, ScoringResult, SpectralAnalysis, TemporalAnalysis, Status as ScoringStatus, Trend } from './scoring-engine';
export { runScoringEngine, DEFAULT_PARAMS, STATUS } from './scoring-engine';
export { ValidationError, buildPaddedStream } from './validate-stream';   
export type AggregationResult = PaddedStreamNode[];   