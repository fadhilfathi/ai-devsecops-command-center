/**
 * In-memory repository of detected incident chains.
 *
 * The chain repository is tenant-scoped and process-local. The
 * Sprint 5 refactor will move this to a persistent store; the
 * shape is already designed for that.
 */
import { randomUUID } from 'node:crypto';
import type { UUID } from '@aicc/shared';
import type { IncidentChain, CorrelationEdge } from './correlation-engine.js';

export interface ChainRepository {
  add(chain: IncidentChain, edges: CorrelationEdge[]): Promise<void>;
  list(tenantId: UUID): Promise<IncidentChain[]>;
  findById(id: UUID, tenantId: UUID): Promise<IncidentChain | undefined>;
  edgesFor(tenantId: UUID): Promise<CorrelationEdge[]>;
}

export function buildChainRepository(): ChainRepository {
  const chains = new Map<string, IncidentChain>();
  const edges = new Map<string, CorrelationEdge[]>();
  return {
    async add(chain, e) {
      chains.set(chain.id, chain);
      const arr = edges.get(chain.tenantId) ?? [];
      arr.push(...e);
      edges.set(chain.tenantId, arr);
      void randomUUID;
    },
    async list(tenantId) {
      return Array.from(chains.values()).filter((c) => c.tenantId === tenantId);
    },
    async findById(id, tenantId) {
      const c = chains.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      return c;
    },
    async edgesFor(tenantId) {
      return edges.get(tenantId) ?? [];
    },
  };
}
