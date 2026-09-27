import type { UUID } from '@aicc/shared';

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
