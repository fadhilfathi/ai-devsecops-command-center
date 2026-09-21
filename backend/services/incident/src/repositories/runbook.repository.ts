import type { Runbook, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateRunbookInput {
  tenantId: UUID;
  name: string;
  description: string;
  steps: Array<{ order: number; title: string; detail: string }>;
  triggers: string[];
}

export interface RunbookRepository {
  list(tenantId: UUID): Promise<Runbook[]>;
  findById(id: UUID, tenantId: UUID): Promise<Runbook | undefined>;
  create(input: CreateRunbookInput): Promise<Runbook>;
  remove(id: UUID, tenantId: UUID): Promise<boolean>;
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

export function buildRunbookRepository(): RunbookRepository {
  const store = new Map<UUID, Runbook>();
  return {
    async list(tenantId) {
      return Array.from(store.values()).filter((r) => r.tenantId === tenantId);
    },
    async findById(id, tenantId) {
      const r = store.get(id);
      if (!r || r.tenantId !== tenantId) return undefined;
      return r;
    },
    async create(input) {
      const now = new Date().toISOString();
      const runbook: Runbook = { id: newId(), ...input, createdAt: now, updatedAt: now };
      store.set(runbook.id, runbook);
      return runbook;
    },
    async remove(id, tenantId) {
      const r = store.get(id);
      if (!r || r.tenantId !== tenantId) return false;
      store.delete(id);
      return true;
    },
  };
}

interface RunbookRow {
  id: UUID;
  tenant_id: UUID;
  name: string;
  description: string;
  steps: Runbook['steps'] | string;
  triggers: string[] | string;
  created_at: string;
  updated_at: string;
}

function jsonField<T>(value: T | string): T {
  return typeof value === 'string' ? (JSON.parse(value) as T) : value;
}

function rowToRunbook(row: RunbookRow): Runbook {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    description: row.description,
    steps: jsonField<Runbook['steps']>(row.steps),
    triggers: jsonField<string[]>(row.triggers),
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgRunbookRepository(db: Queryable): RunbookRepository {
  return {
    async list(tenantId) {
      const { rows } = await db.query<RunbookRow>(
        'SELECT * FROM runbooks WHERE tenant_id = $1 ORDER BY created_at ASC',
        [tenantId],
      );
      return rows.map(rowToRunbook);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<RunbookRow>(
        'SELECT * FROM runbooks WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToRunbook(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<RunbookRow>(
        `INSERT INTO runbooks (id, tenant_id, name, description, steps, triggers)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.name,
          input.description,
          JSON.stringify(input.steps),
          JSON.stringify(input.triggers),
        ],
      );
      return rowToRunbook(rows[0]!);
    },
    async remove(id, tenantId) {
      const { rows } = await db.query(
        'DELETE FROM runbooks WHERE id = $1 AND tenant_id = $2 RETURNING id',
        [id, tenantId],
      );
      return rows.length > 0;
    },
  };
}
