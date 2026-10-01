import type { UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface EvidenceRecord {
  id: UUID;
  tenantId: UUID;
  controlId: UUID;
  kind: 'screenshot' | 'log' | 'config' | 'attestation' | 'other';
  description: string;
  ref: string; // URL or path
  collectedBy: UUID; // userId
  collectedAt: string;
}

export interface EvidenceRepository {
  list(tenantId: UUID, controlId?: UUID): Promise<EvidenceRecord[]>;
  findById(id: UUID, tenantId: UUID): Promise<EvidenceRecord | undefined>;
  /** Look up an existing evidence row by its content-addressed blob ref, for dedup. */
  findByRef(tenantId: UUID, controlId: UUID, ref: string): Promise<EvidenceRecord | undefined>;
  create(input: Omit<EvidenceRecord, 'id' | 'collectedAt'>): Promise<EvidenceRecord>;
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

export function buildEvidenceRepository(): EvidenceRepository {
  const store = new Map<UUID, EvidenceRecord>();
  return {
    async list(tenantId, controlId) {
      return Array.from(store.values()).filter(
        (e) => e.tenantId === tenantId && (!controlId || e.controlId === controlId),
      );
    },
    async findById(id, tenantId) {
      const e = store.get(id);
      if (!e || e.tenantId !== tenantId) return undefined;
      return e;
    },
    async findByRef(tenantId, controlId, ref) {
      return Array.from(store.values()).find(
        (e) => e.tenantId === tenantId && e.controlId === controlId && e.ref === ref,
      );
    },
    async create(input) {
      const record: EvidenceRecord = {
        id: newId(),
        collectedAt: new Date().toISOString(),
        ...input,
      };
      store.set(record.id, record);
      return record;
    },
  };
}

interface EvidenceRow {
  id: UUID;
  tenant_id: UUID;
  control_id: UUID;
  kind: EvidenceRecord['kind'];
  description: string;
  ref: string;
  collected_by: UUID;
  collected_at: string;
}

function rowToEvidence(row: EvidenceRow): EvidenceRecord {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    controlId: row.control_id,
    kind: row.kind,
    description: row.description,
    ref: row.ref,
    collectedBy: row.collected_by,
    collectedAt: new Date(row.collected_at).toISOString(),
  };
}

export function buildPgEvidenceRepository(db: Queryable): EvidenceRepository {
  return {
    async list(tenantId, controlId) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (controlId) {
        params.push(controlId);
        conditions.push(`control_id = $${params.length}`);
      }
      const { rows } = await db.query<EvidenceRow>(
        `SELECT * FROM evidence WHERE ${conditions.join(' AND ')} ORDER BY collected_at ASC`,
        params,
      );
      return rows.map(rowToEvidence);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<EvidenceRow>(
        'SELECT * FROM evidence WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToEvidence(rows[0]) : undefined;
    },
    async findByRef(tenantId, controlId, ref) {
      const { rows } = await db.query<EvidenceRow>(
        'SELECT * FROM evidence WHERE tenant_id = $1 AND control_id = $2 AND ref = $3',
        [tenantId, controlId, ref],
      );
      return rows[0] ? rowToEvidence(rows[0]) : undefined;
    },
    async create(input) {
      const { rows } = await db.query<EvidenceRow>(
        `INSERT INTO evidence
           (id, tenant_id, control_id, kind, description, ref, collected_by, collected_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          newId(),
          input.tenantId,
          input.controlId,
          input.kind,
          input.description,
          input.ref,
          input.collectedBy,
          new Date().toISOString(),
        ],
      );
      return rowToEvidence(rows[0]!);
    },
  };
}
