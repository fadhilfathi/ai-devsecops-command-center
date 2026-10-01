import type { SecurityScan, ScanStatus, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateScanInput {
  assetId: UUID;
  tenantId: UUID;
  scanner: string;
}

export interface ScanRepository {
  list(tenantId: UUID): Promise<SecurityScan[]>;
  findById(id: UUID, tenantId: UUID): Promise<SecurityScan | undefined>;
  create(input: CreateScanInput): Promise<SecurityScan>;
  updateStatus(id: UUID, tenantId: UUID, status: ScanStatus): Promise<SecurityScan | undefined>;
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

export function buildScanRepository(): ScanRepository {
  const store = new Map<UUID, SecurityScan>();
  return {
    async list(tenantId) {
      return Array.from(store.values()).filter((s) => s.tenantId === tenantId);
    },
    async findById(id, tenantId) {
      const s = store.get(id);
      if (!s || s.tenantId !== tenantId) return undefined;
      return s;
    },
    async create(input) {
      const now = new Date().toISOString();
      const scan: SecurityScan = {
        id: newId(),
        tenantId: input.tenantId,
        assetId: input.assetId,
        status: 'queued',
        startedAt: now,
        findingsCount: 0,
        scanner: input.scanner,
        createdAt: now,
        updatedAt: now,
      };
      store.set(scan.id, scan);
      return scan;
    },
    async updateStatus(id, tenantId, status) {
      const s = store.get(id);
      if (!s || s.tenantId !== tenantId) return undefined;
      const next: SecurityScan = { ...s, status, updatedAt: new Date().toISOString() };
      if (status === 'succeeded' || status === 'failed' || status === 'cancelled') {
        next.finishedAt = new Date().toISOString();
      }
      store.set(id, next);
      return next;
    },
  };
}

interface ScanRow {
  id: UUID;
  tenant_id: UUID;
  asset_id: UUID;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  findings_count: number;
  scanner: string;
  created_at: string;
  updated_at: string;
}

function rowToScan(row: ScanRow): SecurityScan {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    assetId: row.asset_id,
    status: row.status,
    startedAt: row.started_at ? new Date(row.started_at).toISOString() : undefined,
    finishedAt: row.finished_at ? new Date(row.finished_at).toISOString() : undefined,
    findingsCount: row.findings_count,
    scanner: row.scanner,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgScanRepository(db: Queryable): ScanRepository {
  return {
    async list(tenantId) {
      const { rows } = await db.query<ScanRow>(
        'SELECT * FROM scans WHERE tenant_id = $1 ORDER BY created_at ASC',
        [tenantId],
      );
      return rows.map(rowToScan);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<ScanRow>(
        'SELECT * FROM scans WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToScan(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const now = new Date().toISOString();
      const { rows } = await db.query<ScanRow>(
        `INSERT INTO scans (id, tenant_id, asset_id, status, started_at, findings_count, scanner)
         VALUES ($1, $2, $3, 'queued', $4, 0, $5)
         RETURNING *`,
        [id, input.tenantId, input.assetId, now, input.scanner],
      );
      return rowToScan(rows[0]!);
    },
    async updateStatus(id, tenantId, status) {
      const finished = status === 'succeeded' || status === 'failed' || status === 'cancelled';
      const { rows } = await db.query<ScanRow>(
        `UPDATE scans SET
           status = $2,
           finished_at = CASE WHEN $3 THEN now() ELSE finished_at END,
           updated_at = now()
         WHERE id = $1 AND tenant_id = $4
         RETURNING *`,
        [id, status, finished, tenantId],
      );
      return rows[0] ? rowToScan(rows[0]) : undefined;
    },
  };
}
