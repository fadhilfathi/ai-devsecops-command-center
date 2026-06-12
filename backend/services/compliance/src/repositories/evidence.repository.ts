import type { UUID } from '@aicc/shared';

export interface EvidenceRecord {
  id: UUID;
  tenantId: UUID;
  controlId: UUID;
  kind: 'screenshot' | 'log' | 'config' | 'attestation' | 'other';
  description: string;
  ref: string;       // URL or path
  collectedBy: UUID; // userId
  collectedAt: string;
}

export interface EvidenceRepository {
  list(tenantId: UUID, controlId?: UUID): Promise<EvidenceRecord[]>;
  findById(id: UUID, tenantId: UUID): Promise<EvidenceRecord | undefined>;
  create(input: Omit<EvidenceRecord, 'id' | 'collectedAt'>): Promise<EvidenceRecord>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
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
