import type { FindingSeverity, UUID, VulnerabilityFinding } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateFindingInput {
  scanId: UUID;
  tenantId: UUID;
  cveId?: string;
  packageName?: string;
  packageVersion?: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  remediation?: string;
}

export interface FindingRepository {
  list(
    tenantId: UUID,
    opts?: { severity?: FindingSeverity; status?: VulnerabilityFinding['status'] },
  ): Promise<VulnerabilityFinding[]>;
  findById(id: UUID, tenantId: UUID): Promise<VulnerabilityFinding | undefined>;
  create(input: CreateFindingInput): Promise<VulnerabilityFinding>;
  updateStatus(
    id: UUID,
    tenantId: UUID,
    status: VulnerabilityFinding['status'],
  ): Promise<VulnerabilityFinding | undefined>;
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

export function buildFindingRepository(): FindingRepository {
  const store = new Map<UUID, VulnerabilityFinding>();
  return {
    async list(tenantId, opts) {
      return Array.from(store.values()).filter(
        (f) =>
          f.tenantId === tenantId &&
          (!opts?.severity || f.severity === opts.severity) &&
          (!opts?.status || f.status === opts.status),
      );
    },
    async findById(id, tenantId) {
      const f = store.get(id);
      if (!f || f.tenantId !== tenantId) return undefined;
      return f;
    },
    async create(input) {
      const now = new Date().toISOString();
      const finding: VulnerabilityFinding = {
        id: newId(),
        tenantId: input.tenantId,
        scanId: input.scanId,
        cveId: input.cveId,
        packageName: input.packageName,
        packageVersion: input.packageVersion,
        severity: input.severity,
        title: input.title,
        description: input.description,
        remediation: input.remediation,
        status: 'open',
        createdAt: now,
        updatedAt: now,
      };
      store.set(finding.id, finding);
      return finding;
    },
    async updateStatus(id, tenantId, status) {
      const f = store.get(id);
      if (!f || f.tenantId !== tenantId) return undefined;
      const next: VulnerabilityFinding = { ...f, status, updatedAt: new Date().toISOString() };
      store.set(id, next);
      return next;
    },
  };
}

interface FindingRow {
  id: UUID;
  tenant_id: UUID;
  scan_id: UUID;
  cve_id: string | null;
  package_name: string | null;
  package_version: string | null;
  severity: FindingSeverity;
  title: string;
  description: string;
  remediation: string | null;
  status: VulnerabilityFinding['status'];
  created_at: string;
  updated_at: string;
}

function rowToFinding(row: FindingRow): VulnerabilityFinding {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    scanId: row.scan_id,
    cveId: row.cve_id ?? undefined,
    packageName: row.package_name ?? undefined,
    packageVersion: row.package_version ?? undefined,
    severity: row.severity,
    title: row.title,
    description: row.description,
    remediation: row.remediation ?? undefined,
    status: row.status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgFindingRepository(db: Queryable): FindingRepository {
  return {
    async list(tenantId, opts) {
      const conditions = ['tenant_id = $1'];
      const params: unknown[] = [tenantId];
      if (opts?.severity) {
        params.push(opts.severity);
        conditions.push(`severity = $${params.length}`);
      }
      if (opts?.status) {
        params.push(opts.status);
        conditions.push(`status = $${params.length}`);
      }
      const { rows } = await db.query<FindingRow>(
        `SELECT * FROM findings WHERE ${conditions.join(' AND ')} ORDER BY created_at ASC`,
        params,
      );
      return rows.map(rowToFinding);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<FindingRow>(
        'SELECT * FROM findings WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToFinding(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<FindingRow>(
        `INSERT INTO findings
           (id, tenant_id, scan_id, cve_id, package_name, package_version, severity, title, description, remediation, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'open')
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.scanId,
          input.cveId ?? null,
          input.packageName ?? null,
          input.packageVersion ?? null,
          input.severity,
          input.title,
          input.description,
          input.remediation ?? null,
        ],
      );
      return rowToFinding(rows[0]!);
    },
    async updateStatus(id, tenantId, status) {
      const { rows } = await db.query<FindingRow>(
        `UPDATE findings SET status = $3, updated_at = now()
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenantId, status],
      );
      return rows[0] ? rowToFinding(rows[0]) : undefined;
    },
  };
}
