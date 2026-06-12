import type { Runbook, UUID } from '@aicc/shared';

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
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
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
