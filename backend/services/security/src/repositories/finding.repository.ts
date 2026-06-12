import type { FindingSeverity, UUID, VulnerabilityFinding } from '@aicc/shared';

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
  list(tenantId: UUID, opts?: { severity?: FindingSeverity; status?: VulnerabilityFinding['status'] }): Promise<VulnerabilityFinding[]>;
  findById(id: UUID, tenantId: UUID): Promise<VulnerabilityFinding | undefined>;
  create(input: CreateFindingInput): Promise<VulnerabilityFinding>;
  updateStatus(id: UUID, tenantId: UUID, status: VulnerabilityFinding['status']): Promise<VulnerabilityFinding | undefined>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
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
