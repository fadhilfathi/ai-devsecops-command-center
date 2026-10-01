import type { ComplianceControl, ComplianceFramework, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateControlInput {
  tenantId: UUID;
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  evidenceRefs?: string[];
}

export interface ControlRepository {
  list(tenantId: UUID, opts?: { framework?: ComplianceFramework }): Promise<ComplianceControl[]>;
  findById(id: UUID, tenantId: UUID): Promise<ComplianceControl | undefined>;
  create(input: CreateControlInput): Promise<ComplianceControl>;
  updateStatus(
    id: UUID,
    tenantId: UUID,
    status: ComplianceControl['status'],
  ): Promise<ComplianceControl | undefined>;
  addEvidence(
    id: UUID,
    tenantId: UUID,
    evidenceRef: string,
  ): Promise<ComplianceControl | undefined>;
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

export function buildControlRepository(): ControlRepository {
  const store = new Map<UUID, ComplianceControl>();
  return {
    async list(tenantId, opts) {
      return Array.from(store.values()).filter(
        (c) => c.tenantId === tenantId && (!opts?.framework || c.framework === opts.framework),
      );
    },
    async findById(id, tenantId) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      return c;
    },
    async create(input) {
      const now = new Date().toISOString();
      const control: ComplianceControl = {
        id: newId(),
        tenantId: input.tenantId,
        framework: input.framework,
        controlId: input.controlId,
        title: input.title,
        description: input.description,
        status: 'manual_review',
        evidenceRefs: input.evidenceRefs ?? [],
        createdAt: now,
        updatedAt: now,
      };
      store.set(control.id, control);
      return control;
    },
    async updateStatus(id, tenantId, status) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      const next: ComplianceControl = { ...c, status, updatedAt: new Date().toISOString() };
      store.set(id, next);
      return next;
    },
    async addEvidence(id, tenantId, evidenceRef) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      if (c.evidenceRefs.includes(evidenceRef)) return c;
      const next: ComplianceControl = {
        ...c,
        evidenceRefs: [...c.evidenceRefs, evidenceRef],
        updatedAt: new Date().toISOString(),
      };
      store.set(id, next);
      return next;
    },
  };
}

interface ControlRow {
  id: UUID;
  tenant_id: UUID;
  framework: ComplianceFramework;
  control_id: string;
  title: string;
  description: string;
  status: ComplianceControl['status'];
  evidence_refs: string[];
  created_at: string;
  updated_at: string;
}

function rowToControl(row: ControlRow): ComplianceControl {
  const evidenceRefs =
    typeof row.evidence_refs === 'string' ? JSON.parse(row.evidence_refs) : row.evidence_refs;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    framework: row.framework,
    controlId: row.control_id,
    title: row.title,
    description: row.description,
    status: row.status,
    evidenceRefs,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgControlRepository(db: Queryable): ControlRepository {
  return {
    async list(tenantId, opts) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (opts?.framework) {
        params.push(opts.framework);
        conditions.push(`framework = $${params.length}`);
      }
      const { rows } = await db.query<ControlRow>(
        `SELECT * FROM controls WHERE ${conditions.join(' AND ')} ORDER BY created_at ASC`,
        params,
      );
      return rows.map(rowToControl);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<ControlRow>(
        'SELECT * FROM controls WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToControl(rows[0]) : undefined;
    },
    async create(input) {
      const now = new Date().toISOString();
      const { rows } = await db.query<ControlRow>(
        `INSERT INTO controls
           (id, tenant_id, framework, control_id, title, description, status, evidence_refs, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'manual_review', $7, $8, $8)
         RETURNING *`,
        [
          newId(),
          input.tenantId,
          input.framework,
          input.controlId,
          input.title,
          input.description,
          JSON.stringify(input.evidenceRefs ?? []),
          now,
        ],
      );
      return rowToControl(rows[0]!);
    },
    async updateStatus(id, tenantId, status) {
      const { rows } = await db.query<ControlRow>(
        `UPDATE controls SET status = $3, updated_at = $4
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenantId, status, new Date().toISOString()],
      );
      return rows[0] ? rowToControl(rows[0]) : undefined;
    },
    async addEvidence(id, tenantId, evidenceRef) {
      const { rows } = await db.query<ControlRow>(
        `UPDATE controls SET
           evidence_refs = CASE
             WHEN evidence_refs @> $3::jsonb THEN evidence_refs
             ELSE evidence_refs || $3::jsonb
           END,
           updated_at = CASE
             WHEN evidence_refs @> $3::jsonb THEN updated_at
             ELSE $4
           END
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenantId, JSON.stringify([evidenceRef]), new Date().toISOString()],
      );
      return rows[0] ? rowToControl(rows[0]) : undefined;
    },
  };
}
