// src/lib/normalize-with-config.ts
// Generic, data-driven normalizer. Applies an AdapterConfig to a raw
// platform payload and produces CanonicalEvent[]. No platform-specific
// code. One implementation for all platforms.

import type { AdapterConfig } from './adapter-config';
import type { CanonicalEvent, Category, Status } from './canonical-event';

function resolvePath(obj: any, path: string): any {
  if (!path) return undefined;
  return path.split('.').reduce((cur: any, key: string) => cur?.[key], obj);
}

function parseTimestamp(value: any, format: 'iso' | 'epoch' | 'epoch_ms'): number {
  if (value === null || value === undefined) return Math.floor(Date.now() / 1000);
  if (format === 'epoch') return Number(value);
  if (format === 'epoch_ms') return Math.floor(Number(value) / 1000);
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? Math.floor(Date.now() / 1000) : Math.floor(parsed / 1000);
}

export function normalizeWithConfig(rawPayload: any, config: AdapterConfig): CanonicalEvent[] {
  let items: any[];

  if (config.isArray) {
    items = Array.isArray(rawPayload) ? rawPayload : [rawPayload];
  } else if (config.arrayItemField) {
    const arr = rawPayload[config.arrayItemField];
    items = Array.isArray(arr) ? arr : [rawPayload];
  } else {
    items = [rawPayload];
  }

  return items.map((item) => ({
    severity: clamp01(
      (resolvePath(item, config.severity.field) ?? config.severity.default) / config.severity.scale
    ),
    category: (config.category.mapping[resolvePath(item, config.category.field)] ?? config.category.default) as Category,
    status: (config.status.mapping[resolvePath(item, config.status.field)] ?? config.status.default) as Status,
    timestamp: parseTimestamp(resolvePath(item, config.timestamp.field), config.timestamp.format),
    entity: String(resolvePath(item, config.entity.field) ?? config.entity.default ?? 'unknown'),
  }));
}

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}