import type { Integration, IntegrationProvider, UUID } from '@aicc/shared';

export interface CreateIntegrationInput {
  tenantId: UUID;
  provider: IntegrationProvider;
  name: string;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface IntegrationRepository {
  list(tenantId: UUID): Promise<Integration[]>;
  findById(id: UUID, tenantId: UUID): Promise<Integration | undefined>;
  create(input: CreateIntegrationInput): Promise<Integration>;
  setEnabled(id: UUID, tenantId: UUID, enabled: boolean): Promise<Integration | undefined>;
  remove(id: UUID, tenantId: UUID): Promise<boolean>;
  recordSync(id: UUID, tenantId: UUID, at: string): Promise<Integration | undefined>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

export function buildIntegrationRepository(): IntegrationRepository {
  const store = new Map<UUID, Integration>();
  return {
    async list(tenantId) {
      return Array.from(store.values()).filter((i) => i.tenantId === tenantId);
    },
    async findById(id, tenantId) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      return i;
    },
    async create(input) {
      const now = new Date().toISOString();
      const integration: Integration = {
        id: newId(),
        tenantId: input.tenantId,
        provider: input.provider,
        name: input.name,
        config: input.config ?? {},
        enabled: input.enabled ?? true,
        createdAt: now,
        updatedAt: now,
      };
      store.set(integration.id, integration);
      return integration;
    },
    async setEnabled(id, tenantId, enabled) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      const next: Integration = { ...i, enabled, updatedAt: new Date().toISOString() };
      store.set(id, next);
      return next;
    },
    async remove(id, tenantId) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return false;
      store.delete(id);
      return true;
    },
    async recordSync(id, tenantId, at) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      const next: Integration = { ...i, lastSyncAt: at, updatedAt: at };
      store.set(id, next);
      return next;
    },
  };
}
