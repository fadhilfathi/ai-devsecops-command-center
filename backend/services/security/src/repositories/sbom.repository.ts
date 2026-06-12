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

export interface SbomRepository {
  list(tenantId: UUID, assetId?: UUID): Promise<SbomRecord[]>;
  findById(id: UUID, tenantId: UUID): Promise<SbomRecord | undefined>;
  create(input: Omit<SbomRecord, 'id' | 'createdAt'>): Promise<SbomRecord>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

export function buildSbomRepository(): SbomRepository {
  const store = new Map<UUID, SbomRecord>();
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
  };
}
