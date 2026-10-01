import type { Asset, AssetType, TenantScoped, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateAssetInput {
  type: AssetType;
  name: string;
  ownerId: UUID;
  tenantId: UUID;
  metadata?: Record<string, unknown>;
  tags?: string[];
}

export interface AssetRepository {
  list(tenantId: UUID): Promise<Asset[]>;
  findById(id: UUID, tenantId: UUID): Promise<Asset | undefined>;
  create(input: CreateAssetInput): Promise<Asset>;
  remove(id: UUID, tenantId: UUID): Promise<boolean>;
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

export function buildAssetRepository(): AssetRepository {
  const store = new Map<UUID, Asset>();
  return {
    async list(tenantId) {
      return Array.from(store.values()).filter((a) => a.tenantId === tenantId);
    },
    async findById(id, tenantId) {
      const a = store.get(id);
      if (!a || a.tenantId !== tenantId) return undefined;
      return a;
    },
    async create(input) {
      const now = new Date().toISOString();
      const asset: Asset = {
        id: newId(),
        tenantId: input.tenantId,
        type: input.type,
        name: input.name,
        ownerId: input.ownerId,
        metadata: input.metadata ?? {},
        tags: input.tags ?? [],
        createdAt: now,
        updatedAt: now,
      } as Asset & TenantScoped;
      store.set(asset.id, asset);
      return asset;
    },
    async remove(id, tenantId) {
      const a = store.get(id);
      if (!a || a.tenantId !== tenantId) return false;
      store.delete(id);
      return true;
    },
  };
}

interface AssetRow {
  id: UUID;
  tenant_id: UUID;
  type: AssetType;
  name: string;
  owner_id: UUID;
  metadata: Record<string, unknown>;
  tags: string[];
  created_at: string;
  updated_at: string;
}

function rowToAsset(row: AssetRow): Asset {
  const metadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
  const tags = typeof row.tags === 'string' ? JSON.parse(row.tags) : row.tags;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    type: row.type,
    name: row.name,
    ownerId: row.owner_id,
    metadata,
    tags,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgAssetRepository(db: Queryable): AssetRepository {
  return {
    async list(tenantId) {
      const { rows } = await db.query<AssetRow>(
        'SELECT * FROM assets WHERE tenant_id = $1 ORDER BY created_at ASC',
        [tenantId],
      );
      return rows.map(rowToAsset);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<AssetRow>(
        'SELECT * FROM assets WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      return rows[0] ? rowToAsset(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<AssetRow>(
        `INSERT INTO assets (id, tenant_id, type, name, owner_id, metadata, tags)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.type,
          input.name,
          input.ownerId,
          JSON.stringify(input.metadata ?? {}),
          JSON.stringify(input.tags ?? []),
        ],
      );
      return rowToAsset(rows[0]!);
    },
    async remove(id, tenantId) {
      const { rows } = await db.query(
        'DELETE FROM assets WHERE id = $1 AND tenant_id = $2 RETURNING id',
        [id, tenantId],
      );
      return rows.length > 0;
    },
  };
}
