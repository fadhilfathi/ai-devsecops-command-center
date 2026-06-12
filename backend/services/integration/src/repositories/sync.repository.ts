import type { UUID } from '@aicc/shared';

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
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
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
