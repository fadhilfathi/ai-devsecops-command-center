import type { UUID } from '@aicc/shared';
import { withTransaction, type Queryable } from '@aicc/shared/db';

export type SbomFormat = 'cyclonedx' | 'spdx';

export interface SbomRecord {
  id: UUID;
  tenantId: UUID;
  assetId: UUID;
  format: SbomFormat;
  document: unknown;
  createdAt: string;
}

/**
 * S10-2 — one row per SBOM component, extracted from the raw document at
 * ingest time (see `security-analytics.ts`'s `computeSbomIndex`) so the
 * analytics routes never re-parse the CycloneDX document per request.
 */
export interface SbomComponentRecord {
  tenantId: UUID;
  sbomId: UUID;
  assetId: UUID;
  id: string;
  name: string;
  version: string;
  purl: string;
  license: string;
  supplier?: string;
  ecosystem: string;
  depth: number;
}

/** One dependency-graph edge between two component `bom-ref`s, scoped to a single SBOM. */
export interface SbomEdgeRecord {
  tenantId: UUID;
  sbomId: UUID;
  source: string;
  target: string;
}

export interface SbomRepository {
  list(tenantId: UUID, assetId?: UUID): Promise<SbomRecord[]>;
  findById(id: UUID, tenantId: UUID): Promise<SbomRecord | undefined>;
  create(input: Omit<SbomRecord, 'id' | 'createdAt'>): Promise<SbomRecord>;
  listComponents(tenantId: UUID, opts?: { sbomId?: UUID }): Promise<SbomComponentRecord[]>;
  listEdges(tenantId: UUID, opts?: { sbomId?: UUID }): Promise<SbomEdgeRecord[]>;
  /** Replaces the stored component index for one SBOM (no orphans on re-ingest). */
  replaceComponents(
    tenantId: UUID,
    sbomId: UUID,
    assetId: UUID,
    components: Array<Omit<SbomComponentRecord, 'tenantId' | 'sbomId' | 'assetId'>>,
    edges: Array<Omit<SbomEdgeRecord, 'tenantId' | 'sbomId'>>,
  ): Promise<void>;
}

function newId(): UUID {
  return (
    globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    })
  );
}

export function buildSbomRepository(): SbomRepository {
  const store = new Map<UUID, SbomRecord>();
  const componentsBySbom = new Map<UUID, SbomComponentRecord[]>();
  const edgesBySbom = new Map<UUID, SbomEdgeRecord[]>();
  return {
    async list(tenantId, assetId) {
      return Array.from(store.values()).filter(
        (s) => s.tenantId === tenantId && (!assetId || s.assetId === assetId),
      );
    },
    async findById(id, tenantId) {
      const s = store.get(id);
      if (!s || s.tenantId !== tenantId) return undefined;
      return s;
    },
    async create(input) {
      const record: SbomRecord = {
        id: newId(),
        createdAt: new Date().toISOString(),
        ...input,
      };
      store.set(record.id, record);
      return record;
    },
    async listComponents(tenantId, opts) {
      const all = Array.from(componentsBySbom.values())
        .flat()
        .filter((c) => c.tenantId === tenantId);
      return opts?.sbomId ? all.filter((c) => c.sbomId === opts.sbomId) : all;
    },
    async listEdges(tenantId, opts) {
      const all = Array.from(edgesBySbom.values())
        .flat()
        .filter((e) => e.tenantId === tenantId);
      return opts?.sbomId ? all.filter((e) => e.sbomId === opts.sbomId) : all;
    },
    async replaceComponents(tenantId, sbomId, assetId, components, edges) {
      // The index is keyed by sbomId, so refuse to write one that belongs
      // to another tenant.
      if (store.get(sbomId)?.tenantId !== tenantId) {
        throw new Error(`sbom ${sbomId} not found for tenant`);
      }
      componentsBySbom.set(
        sbomId,
        components.map((c) => ({ ...c, tenantId, sbomId, assetId })),
      );
      edgesBySbom.set(
        sbomId,
        edges.map((e) => ({ ...e, tenantId, sbomId })),
      );
    },
  };
}

interface SbomRow {
  id: UUID;
  tenant_id: UUID;
  asset_id: UUID;
  format: SbomFormat;
  document: unknown;
  created_at: string;
}

function rowToSbom(row: SbomRow): SbomRecord {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    assetId: row.asset_id,
    format: row.format,
    document: typeof row.document === 'string' ? JSON.parse(row.document) : row.document,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

interface SbomComponentRow {
  tenant_id: UUID;
  sbom_id: UUID;
  asset_id: UUID;
  component_id: string;
  name: string;
  version: string;
  purl: string;
  license: string;
  supplier: string | null;
  ecosystem: string;
  depth: number;
}

function rowToComponent(row: SbomComponentRow): SbomComponentRecord {
  return {
    tenantId: row.tenant_id,
    sbomId: row.sbom_id,
    assetId: row.asset_id,
    id: row.component_id,
    name: row.name,
    version: row.version,
    purl: row.purl,
    license: row.license,
    supplier: row.supplier ?? undefined,
    ecosystem: row.ecosystem,
    depth: row.depth,
  };
}

interface SbomEdgeRow {
  tenant_id: UUID;
  sbom_id: UUID;
  source: string;
  target: string;
}

function rowToEdge(row: SbomEdgeRow): SbomEdgeRecord {
  return { tenantId: row.tenant_id, sbomId: row.sbom_id, source: row.source, target: row.target };
}

export function buildPgSbomRepository(db: Queryable): SbomRepository {
  return {
    async list(tenantId, assetId) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (assetId) {
        params.push(assetId);
        conditions.push(`asset_id = $${params.length}`);
      }
      const { rows } = await db.query<SbomRow>(
        `SELECT * FROM sboms WHERE ${conditions.join(' AND ')} ORDER BY created_at ASC`,
        params,
      );
      return rows.map(rowToSbom);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<SbomRow>(
        'SELECT * FROM sboms WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToSbom(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<SbomRow>(
        `INSERT INTO sboms (id, tenant_id, asset_id, format, document)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [id, input.tenantId, input.assetId, input.format, JSON.stringify(input.document)],
      );
      return rowToSbom(rows[0]!);
    },
    async listComponents(tenantId, opts) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (opts?.sbomId) {
        params.push(opts.sbomId);
        conditions.push(`sbom_id = $${params.length}`);
      }
      const { rows } = await db.query<SbomComponentRow>(
        `SELECT * FROM sbom_components WHERE ${conditions.join(' AND ')}`,
        params,
      );
      return rows.map(rowToComponent);
    },
    async listEdges(tenantId, opts) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (opts?.sbomId) {
        params.push(opts.sbomId);
        conditions.push(`sbom_id = $${params.length}`);
      }
      const { rows } = await db.query<SbomEdgeRow>(
        `SELECT * FROM sbom_edges WHERE ${conditions.join(' AND ')}`,
        params,
      );
      return rows.map(rowToEdge);
    },
    async replaceComponents(tenantId, sbomId, assetId, components, edges) {
      await withTransaction(db, async (tx) => {
        const { rows } = await tx.query<{ tenant_id: UUID }>(
          'SELECT tenant_id FROM sboms WHERE id = $1',
          [sbomId],
        );
        if (rows[0]?.tenant_id !== tenantId) {
          throw new Error(`sbom ${sbomId} not found for tenant`);
        }
        await tx.query('DELETE FROM sbom_components WHERE sbom_id = $1', [sbomId]);
        await tx.query('DELETE FROM sbom_edges WHERE sbom_id = $1', [sbomId]);
        for (const c of components) {
          await tx.query(
            `INSERT INTO sbom_components
               (tenant_id, sbom_id, asset_id, component_id, name, version, purl, license, supplier, ecosystem, depth)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [
              tenantId,
              sbomId,
              assetId,
              c.id,
              c.name,
              c.version,
              c.purl,
              c.license,
              c.supplier ?? null,
              c.ecosystem,
              c.depth,
            ],
          );
        }
        for (const e of edges) {
          await tx.query(
            `INSERT INTO sbom_edges (tenant_id, sbom_id, source, target) VALUES ($1, $2, $3, $4)`,
            [tenantId, sbomId, e.source, e.target],
          );
        }
      });
    },
  };
}
