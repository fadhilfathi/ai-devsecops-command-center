/**
 * In-memory repository of detected incident chains.
 *
 * The chain repository is tenant-scoped and process-local. The
 * Sprint 5 refactor will move this to a persistent store; the
 * shape is already designed for that.
 */
import { randomUUID } from 'node:crypto';
import type { UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';
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

interface ChainRow {
  id: string;
  tenant_id: UUID;
  root_event_id: string;
  event_ids: string[] | string;
  edges: CorrelationEdge[] | string;
  severity: IncidentChain['severity'];
  title: string;
  summary: string;
  created_at: string;
}

interface EdgeRow {
  id: string;
  source: string;
  target: string;
  kind: CorrelationEdge['kind'];
  weight: number;
  rationale: string;
}

function jsonField<T>(value: T | string): T {
  return typeof value === 'string' ? (JSON.parse(value) as T) : value;
}

function rowToChain(row: ChainRow): IncidentChain {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    rootEventId: row.root_event_id,
    eventIds: jsonField<string[]>(row.event_ids),
    edges: jsonField<CorrelationEdge[]>(row.edges),
    severity: row.severity,
    title: row.title,
    summary: row.summary,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function rowToEdge(row: EdgeRow): CorrelationEdge {
  return {
    id: row.id,
    source: row.source,
    target: row.target,
    kind: row.kind,
    weight: row.weight,
    rationale: row.rationale,
  };
}

/** Postgres-backed chain repository. `edges` are also fanned out into the
 * per-tenant `correlation_edges` table for `edgesFor()`; the chain's own
 * edges (the subset that participate in it) stay denormalised on the
 * `incident_chains.edges` jsonb column, matching the in-memory shape. */
export function buildPgChainRepository(db: Queryable): ChainRepository {
  return {
    async add(chain, edgesIn) {
      await db.query(
        `INSERT INTO incident_chains
           (id, tenant_id, root_event_id, event_ids, edges, severity, title, summary, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          chain.id,
          chain.tenantId,
          chain.rootEventId,
          JSON.stringify(chain.eventIds),
          JSON.stringify(chain.edges),
          chain.severity,
          chain.title,
          chain.summary,
          chain.createdAt,
        ],
      );
      for (const edge of edgesIn) {
        await db.query(
          `INSERT INTO correlation_edges (id, tenant_id, source, target, kind, weight, rationale)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            randomUUID(),
            chain.tenantId,
            edge.source,
            edge.target,
            edge.kind,
            edge.weight,
            edge.rationale,
          ],
        );
      }
    },
    async list(tenantId) {
      const { rows } = await db.query<ChainRow>(
        'SELECT * FROM incident_chains WHERE tenant_id = $1 ORDER BY created_at ASC',
        [tenantId],
      );
      return rows.map(rowToChain);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<ChainRow>(
        'SELECT * FROM incident_chains WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToChain(rows[0]) : undefined;
    },
    async edgesFor(tenantId) {
      const { rows } = await db.query<EdgeRow>(
        'SELECT id, source, target, kind, weight, rationale FROM correlation_edges WHERE tenant_id = $1 ORDER BY created_at ASC',
        [tenantId],
      );
      return rows.map(rowToEdge);
    },
  };
}
