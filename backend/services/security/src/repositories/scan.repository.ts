import type { SecurityScan, ScanStatus, UUID } from '@aicc/shared';

export interface CreateScanInput {
  assetId: UUID;
  tenantId: UUID;
  scanner: string;
}

export interface ScanRepository {
  list(tenantId: UUID): Promise<SecurityScan[]>;
  findById(id: UUID, tenantId: UUID): Promise<SecurityScan | undefined>;
  create(input: CreateScanInput): Promise<SecurityScan>;
  updateStatus(id: UUID, status: ScanStatus): Promise<SecurityScan | undefined>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
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
    async updateStatus(id, status) {
      const s = store.get(id);
      if (!s) return undefined;
      const next: SecurityScan = { ...s, status, updatedAt: new Date().toISOString() };
      if (status === 'succeeded' || status === 'failed' || status === 'cancelled') {
        next.finishedAt = new Date().toISOString();
      }
      store.set(id, next);
      return next;
    },
  };
}
