// POA&M in-memory repository
//
// Process-local in-memory store for Sprint 2. The interface is async
// and persistence-shaped so the Sprint 3 swap to Postgres requires no
// service-layer changes.
//
// Indexes:
//   - by poamId (primary)
//   - by (tenantId, status) for the GET /poam endpoint
//   - by (tenantId, controlId, vulnId, status='open') for dedup
//   - by (tenantId, status, dueAt) for the overdue scheduler

import { randomUUID } from 'node:crypto';
import type { PoamItem, ListPoamFilter, PoamStatus, Framework } from './poam.types.js';

export interface PoamRepository {
  create(item: PoamItem): Promise<PoamItem>;
  getById(tenantId: string, poamId: string): Promise<PoamItem | null>;
  findOpenForControlVuln(
    tenantId: string,
    controlId: string,
    vulnId: string,
  ): Promise<PoamItem | null>;
  list(filter: ListPoamFilter & { tenantId: string }): Promise<{ items: PoamItem[]; nextCursor: string | null }>;
  update(tenantId: string, poamId: string, patch: Partial<PoamItem>): Promise<PoamItem>;
  /** Used by the scheduler: return all open items with dueAt <= now. */
  findOverdue(tenantId: string, now: string, framework?: Framework): Promise<PoamItem[]>;
  /** Used by the scheduler: return all open items grouped by tenant. */
  findAllOpenGroupedByTenant(): Promise<Map<string, PoamItem[]>>;
}

/**
 * Factory for a process-local in-memory POA&M repository. Sprint 3
 * will add a `buildPostgresPoamRepository` factory without changing
 * call sites.
 */
export function buildPoamRepository(): PoamRepository {
  const items = new Map<string, PoamItem>(); // key = poamId

  return {
    async create(item: PoamItem): Promise<PoamItem> {
      const copy = { ...item, evidenceRefs: [...item.evidenceRefs], metadata: { ...item.metadata } };
      items.set(item.poamId, copy);
      return { ...copy };
    },

    async getById(tenantId: string, poamId: string): Promise<PoamItem | null> {
      const item = items.get(poamId);
      if (!item) return null;
      if (item.tenantId !== tenantId) return null;
      return { ...item };
    },

    async findOpenForControlVuln(
      tenantId: string,
      controlId: string,
      vulnId: string,
    ): Promise<PoamItem | null> {
      for (const item of items.values()) {
        if (item.tenantId !== tenantId) continue;
        if (item.controlId !== controlId) continue;
        if (item.vulnId !== vulnId) continue;
        if (item.status === 'closed' || item.status === 'risk_accepted') continue;
        return { ...item };
      }
      return null;
    },

    async list(filter: ListPoamFilter & { tenantId: string }): Promise<{ items: PoamItem[]; nextCursor: string | null }> {
      const limit = Math.min(Math.max(filter.limit ?? 50, 1), 200);
      const matches: PoamItem[] = [];
      for (const item of items.values()) {
        if (item.tenantId !== filter.tenantId) continue;
        if (filter.controlId && item.controlId !== filter.controlId) continue;
        if (filter.framework && item.framework !== filter.framework) continue;
        if (filter.vulnId && item.vulnId !== filter.vulnId) continue;
        if (filter.dueBefore && item.dueAt > filter.dueBefore) continue;
        if (filter.dueAfter && item.dueAt < filter.dueAfter) continue;
        if (filter.status && filter.status !== 'all') {
          if (filter.status === 'overdue') {
            const isOpen = item.status === 'open' || item.status === 'in_progress' || item.status === 'awaiting_evidence';
            if (!isOpen) continue;
            if (Date.parse(item.dueAt) > Date.now()) continue;
          } else if (item.status !== filter.status) {
            continue;
          }
        }
        matches.push(item);
      }
      matches.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const startIdx = filter.cursor ? parseInt(filter.cursor, 10) : 0;
      const slice = matches.slice(startIdx, startIdx + limit);
      const nextIdx = startIdx + slice.length;
      const nextCursor = nextIdx < matches.length ? String(nextIdx) : null;
      return { items: slice.map((i) => ({ ...i })), nextCursor };
    },

    async update(tenantId: string, poamId: string, patch: Partial<PoamItem>): Promise<PoamItem> {
      const existing = items.get(poamId);
      if (!existing || existing.tenantId !== tenantId) {
        throw new Error(`POA&M ${poamId} not found`);
      }
      const next: PoamItem = { ...existing, ...patch, poamId: existing.poamId, tenantId: existing.tenantId };
      items.set(poamId, next);
      return { ...next };
    },

    async findOverdue(tenantId: string, now: string, framework?: Framework): Promise<PoamItem[]> {
      const out: PoamItem[] = [];
      for (const item of items.values()) {
        if (item.tenantId !== tenantId) continue;
        if (framework && item.framework !== framework) continue;
        if (item.status !== 'open' && item.status !== 'in_progress' && item.status !== 'awaiting_evidence') continue;
        if (Date.parse(item.dueAt) > Date.parse(now)) continue;
        out.push({ ...item });
      }
      return out;
    },

    async findAllOpenGroupedByTenant(): Promise<Map<string, PoamItem[]>> {
      const out = new Map<string, PoamItem[]>();
      for (const item of items.values()) {
        if (item.status === 'closed' || item.status === 'risk_accepted') continue;
        const list = out.get(item.tenantId) ?? [];
        list.push(item);
        out.set(item.tenantId, list);
      }
      return out;
    },
  };
}

export { type PoamStatus, type Framework };
