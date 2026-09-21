import type { Incident, IncidentSeverity, IncidentStatus, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateIncidentInput {
  tenantId: UUID;
  title: string;
  description: string;
  severity: IncidentSeverity;
  relatedFindingIds?: UUID[];
  runbookId?: UUID;
  assigneeId?: UUID;
}

export interface IncidentRepository {
  list(
    tenantId: UUID,
    opts?: { status?: IncidentStatus; severity?: IncidentSeverity },
  ): Promise<Incident[]>;
  findById(id: UUID, tenantId: UUID): Promise<Incident | undefined>;
  create(input: CreateIncidentInput): Promise<Incident>;
  update(id: UUID, tenantId: UUID, patch: Partial<Incident>): Promise<Incident | undefined>;
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

export function buildIncidentRepository(): IncidentRepository {
  const store = new Map<UUID, Incident>();
  return {
    async list(tenantId, opts) {
      return Array.from(store.values()).filter(
        (i) =>
          i.tenantId === tenantId &&
          (!opts?.status || i.status === opts.status) &&
          (!opts?.severity || i.severity === opts.severity),
      );
    },
    async findById(id, tenantId) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      return i;
    },
    async create(input) {
      const now = new Date().toISOString();
      const incident: Incident = {
        id: newId(),
        tenantId: input.tenantId,
        title: input.title,
        description: input.description,
        severity: input.severity,
        status: 'open',
        assigneeId: input.assigneeId,
        relatedFindingIds: input.relatedFindingIds ?? [],
        runbookId: input.runbookId,
        createdAt: now,
        updatedAt: now,
      };
      store.set(incident.id, incident);
      return incident;
    },
    async update(id, tenantId, patch) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      const next: Incident = { ...i, ...patch, updatedAt: new Date().toISOString() };
      store.set(id, next);
      return next;
    },
  };
}

interface IncidentRow {
  id: UUID;
  tenant_id: UUID;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assignee_id: UUID | null;
  related_finding_ids: UUID[] | string;
  runbook_id: UUID | null;
  created_at: string;
  updated_at: string;
}

function jsonField<T>(value: T | string): T {
  return typeof value === 'string' ? (JSON.parse(value) as T) : value;
}

function rowToIncident(row: IncidentRow): Incident {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    status: row.status,
    assigneeId: row.assignee_id ?? undefined,
    relatedFindingIds: jsonField<UUID[]>(row.related_finding_ids),
    runbookId: row.runbook_id ?? undefined,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgIncidentRepository(db: Queryable): IncidentRepository {
  return {
    async list(tenantId, opts) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (opts?.status) {
        params.push(opts.status);
        conditions.push(`status = $${params.length}`);
      }
      if (opts?.severity) {
        params.push(opts.severity);
        conditions.push(`severity = $${params.length}`);
      }
      const { rows } = await db.query<IncidentRow>(
        `SELECT * FROM incidents WHERE ${conditions.join(' AND ')} ORDER BY created_at ASC`,
        params,
      );
      return rows.map(rowToIncident);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<IncidentRow>(
        'SELECT * FROM incidents WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToIncident(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<IncidentRow>(
        `INSERT INTO incidents
           (id, tenant_id, title, description, severity, status, assignee_id,
            related_finding_ids, runbook_id)
         VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.title,
          input.description,
          input.severity,
          input.assigneeId ?? null,
          JSON.stringify(input.relatedFindingIds ?? []),
          input.runbookId ?? null,
        ],
      );
      return rowToIncident(rows[0]!);
    },
    async update(id, tenantId, patch) {
      const existing = await this.findById(id, tenantId);
      if (!existing) return undefined;
      const next = { ...existing, ...patch };
      const { rows } = await db.query<IncidentRow>(
        `UPDATE incidents SET
           title = $3, description = $4, severity = $5, status = $6,
           assignee_id = $7, related_finding_ids = $8, runbook_id = $9,
           updated_at = now()
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [
          id,
          tenantId,
          next.title,
          next.description,
          next.severity,
          next.status,
          next.assigneeId ?? null,
          JSON.stringify(next.relatedFindingIds ?? []),
          next.runbookId ?? null,
        ],
      );
      return rows[0] ? rowToIncident(rows[0]) : undefined;
    },
  };
}
