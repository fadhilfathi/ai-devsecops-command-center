import type { Asset, AssetType, TenantScoped, UUID } from '@aicc/shared';

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
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
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
