// src/lib/adapter-config.ts
// Data-driven adapter configuration. Stored per-tenant in KV
// at key `adapter:${tenantId}`. The generic normalizer applies this
// config to raw platform payloads without any platform-specific code.

import type { Category, Status } from './canonical-event';

export interface AdapterConfig {
  platform: string;
  isArray: boolean;
  arrayItemField?: string;
  severity: {
    field: string;
    scale: number;
    default: number;
  };
  category: {
    field: string;
    mapping: Record<string, Category>;
    default: Category;
  };
  status: {
    field: string;
    mapping: Record<string, Status>;
    default: Status;
  };
  timestamp: {
    field: string;
    format: 'iso' | 'epoch' | 'epoch_ms';
  };
  entity: {
    field: string;
    default: string;
  };
}

export function validateAdapterConfig(cfg: any): string | null {
  if (typeof cfg !== 'object' || cfg === null) return 'Config must be an object';
  if (!cfg.platform || typeof cfg.platform !== 'string') return 'platform is required (string)';
  if (typeof cfg.isArray !== 'boolean') return 'isArray is required (boolean)';
  if (cfg.isArray === true && cfg.arrayItemField) return 'arrayItemField is not valid when isArray is true';

  if (!cfg.severity || typeof cfg.severity !== 'object') return 'severity block is required';
  if (!cfg.severity.field) return 'severity.field is required';
  if (typeof cfg.severity.scale !== 'number' || cfg.severity.scale < 1) return 'severity.scale must be >= 1';

  if (!cfg.category || typeof cfg.category !== 'object') return 'category block is required';
  if (!cfg.category.field) return 'category.field is required';
  if (!cfg.category.default) return 'category.default is required';

  if (!cfg.status || typeof cfg.status !== 'object') return 'status block is required';
  if (!cfg.status.field) return 'status.field is required';
  if (!cfg.status.default) return 'status.default is required';

  if (!cfg.timestamp || typeof cfg.timestamp !== 'object') return 'timestamp block is required';
  if (!cfg.timestamp.field) return 'timestamp.field is required';
  if (!['iso', 'epoch', 'epoch_ms'].includes(cfg.timestamp.format)) return 'timestamp.format must be iso, epoch, or epoch_ms';

  if (!cfg.entity || typeof cfg.entity !== 'object') return 'entity block is required';
  if (!cfg.entity.field) return 'entity.field is required';

  return null;
}   