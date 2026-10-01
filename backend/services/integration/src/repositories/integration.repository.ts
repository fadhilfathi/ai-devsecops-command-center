import type { Integration, IntegrationProvider, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

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
  return (
    globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    })
  );
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

interface IntegrationRow {
  id: UUID;
  tenant_id: UUID;
  provider: IntegrationProvider;
  name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  last_sync_at: string | null;
  created_at: string;
  updated_at: string;
}

function rowToIntegration(row: IntegrationRow): Integration {
  const config = typeof row.config === 'string' ? JSON.parse(row.config) : row.config;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    provider: row.provider,
    name: row.name,
    config,
    enabled: row.enabled,
    lastSyncAt: row.last_sync_at ? new Date(row.last_sync_at).toISOString() : undefined,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgIntegrationRepository(db: Queryable): IntegrationRepository {
  return {
    async list(tenantId) {
      const { rows } = await db.query<IntegrationRow>(
        'SELECT * FROM integrations WHERE tenant_id = $1 ORDER BY created_at ASC',
        [tenantId],
      );
      return rows.map(rowToIntegration);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<IntegrationRow>(
        'SELECT * FROM integrations WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToIntegration(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<IntegrationRow>(
        `INSERT INTO integrations (id, tenant_id, provider, name, config, enabled)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.provider,
          input.name,
          JSON.stringify(input.config ?? {}),
          input.enabled ?? true,
        ],
      );
      return rowToIntegration(rows[0]!);
    },
    async setEnabled(id, tenantId, enabled) {
      const { rows } = await db.query<IntegrationRow>(
        `UPDATE integrations SET enabled = $3, updated_at = now()
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenantId, enabled],
      );
      return rows[0] ? rowToIntegration(rows[0]) : undefined;
    },
    async remove(id, tenantId) {
      const { rows } = await db.query(
        'DELETE FROM integrations WHERE id = $1 AND tenant_id = $2 RETURNING id',
        [id, tenantId],
      );
      return rows.length > 0;
    },
    async recordSync(id, tenantId, at) {
      const { rows } = await db.query<IntegrationRow>(
        `UPDATE integrations SET last_sync_at = $3, updated_at = $3
         WHERE id = $1 AND tenant_id = $2
         RETURNING *`,
        [id, tenantId, at],
      );
      return rows[0] ? rowToIntegration(rows[0]) : undefined;
    },
  };
}
