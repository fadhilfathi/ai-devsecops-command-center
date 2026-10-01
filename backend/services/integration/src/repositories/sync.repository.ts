import type { UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export type SyncStatus = 'queued' | 'running' | 'succeeded' | 'failed';

export interface SyncRecord {
  id: UUID;
  tenantId: UUID;
  integrationId: UUID;
  kind: string;
  status: SyncStatus;
  startedAt: string;
  finishedAt?: string;
  error?: string;
  metadata: Record<string, unknown>;
}

export interface SyncRepository {
  list(tenantId: UUID, opts?: { integrationId?: UUID; status?: SyncStatus }): Promise<SyncRecord[]>;
  create(input: Omit<SyncRecord, 'id' | 'startedAt'>): Promise<SyncRecord>;
  finish(id: UUID, status: SyncStatus, error?: string): Promise<SyncRecord | undefined>;
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

export function buildSyncRepository(): SyncRepository {
  const store = new Map<UUID, SyncRecord>();
  return {
    async list(tenantId, opts) {
      return Array.from(store.values()).filter(
        (s) =>
          s.tenantId === tenantId &&
          (!opts?.integrationId || s.integrationId === opts.integrationId) &&
          (!opts?.status || s.status === opts.status),
      );
    },
    async create(input) {
      const record: SyncRecord = { id: newId(), startedAt: new Date().toISOString(), ...input };
      store.set(record.id, record);
      return record;
    },
    async finish(id, status, error) {
      const s = store.get(id);
      if (!s) return undefined;
      const next: SyncRecord = { ...s, status, finishedAt: new Date().toISOString(), error };
      store.set(id, next);
      return next;
    },
  };
}

interface SyncRow {
  id: UUID;
  tenant_id: UUID;
  integration_id: UUID;
  kind: string;
  status: SyncStatus;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  metadata: Record<string, unknown>;
}

function rowToSync(row: SyncRow): SyncRecord {
  const metadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    integrationId: row.integration_id,
    kind: row.kind,
    status: row.status,
    startedAt: new Date(row.started_at).toISOString(),
    finishedAt: row.finished_at ? new Date(row.finished_at).toISOString() : undefined,
    error: row.error ?? undefined,
    metadata,
  };
}

export function buildPgSyncRepository(db: Queryable): SyncRepository {
  return {
    async list(tenantId, opts) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (opts?.integrationId) {
        params.push(opts.integrationId);
        conditions.push(`integration_id = $${params.length}`);
      }
      if (opts?.status) {
        params.push(opts.status);
        conditions.push(`status = $${params.length}`);
      }
      const { rows } = await db.query<SyncRow>(
        `SELECT * FROM syncs WHERE ${conditions.join(' AND ')} ORDER BY started_at ASC`,
        params,
      );
      return rows.map(rowToSync);
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<SyncRow>(
        `INSERT INTO syncs (id, tenant_id, integration_id, kind, status, started_at, finished_at, error, metadata)
         VALUES ($1, $2, $3, $4, $5, now(), $6, $7, $8)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.integrationId,
          input.kind,
          input.status,
          input.finishedAt ?? null,
          input.error ?? null,
          JSON.stringify(input.metadata ?? {}),
        ],
      );
      return rowToSync(rows[0]!);
    },
    async finish(id, status, error) {
      const { rows } = await db.query<SyncRow>(
        `UPDATE syncs SET status = $2, finished_at = now(), error = $3
         WHERE id = $1
         RETURNING *`,
        [id, status, error ?? null],
      );
      return rows[0] ? rowToSync(rows[0]) : undefined;
    },
  };
}
