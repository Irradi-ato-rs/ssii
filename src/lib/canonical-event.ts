// src/lib/canonical-event.ts
// Shared canonical event schema. The single source of truth for the
// aggregation stage. Platform adapters normalize into this shape.

export type Category =
  | 'identity'
  | 'access'
  | 'admin'
  | 'policy'
  | 'governance'
  | 'compliance'
  | 'physical'
  | 'facilities'
  | 'vulnerability'
  | 'network'
  | 'endpoint'
  | 'cloud'
  | 'data';

export type Status =
  | 'open'
  | 'detected'
  | 'resolved'
  | 'suppressed'
  | 'success'
  | 'failure';

export interface CanonicalEvent {
  severity: number;       // 0.0 – 1.0 (normalized)
  category: Category;
  status: Status;
  timestamp: number;      // epoch seconds
  entity: string;         // asset/actor identifier
}

export const ALL_CATEGORIES: Category[] = [
  'identity', 'access', 'admin', 'policy', 'governance', 'compliance',
  'physical', 'facilities', 'vulnerability', 'network', 'endpoint', 'cloud', 'data',
];

export const ALL_STATUSES: Status[] = [
  'open', 'detected', 'resolved', 'suppressed', 'success', 'failure',
];