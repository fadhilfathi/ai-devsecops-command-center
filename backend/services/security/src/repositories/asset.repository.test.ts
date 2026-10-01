import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildAssetRepository,
  buildPgAssetRepository,
  type AssetRepository,
} from './asset.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<AssetRepository> {
  return buildPgAssetRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildAssetRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s asset repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';
  const owner = '00000000-0000-4000-8000-000000000001';

  it('creates and lists assets scoped by tenant', async () => {
    const repo = await build();
    await repo.create({ tenantId: tenantA, type: 'service', name: 'a1', ownerId: owner });
    await repo.create({ tenantId: tenantB, type: 'service', name: 'b1', ownerId: owner });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({ name: 'a1', tenantId: tenantA });

    const listB = await repo.list(tenantB);
    expect(listB).toHaveLength(1);
    expect(listB[0]?.name).toBe('b1');
  });

  it('preserves metadata and tags', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      type: 'repository',
      name: 'repo1',
      ownerId: owner,
      metadata: { language: 'ts' },
      tags: ['demo', 'core'],
    });
    expect(created.metadata).toEqual({ language: 'ts' });
    expect(created.tags).toEqual(['demo', 'core']);
    const found = await repo.findById(created.id, tenantA);
    expect(found?.metadata).toEqual({ language: 'ts' });
    expect(found?.tags).toEqual(['demo', 'core']);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      type: 'service',
      name: 'c1',
      ownerId: owner,
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('remove deletes only the tenant-owned asset', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      type: 'service',
      name: 'c2',
      ownerId: owner,
    });
    expect(await repo.remove(created.id, tenantB)).toBe(false);
    expect(await repo.remove(created.id, tenantA)).toBe(true);
    expect(await repo.findById(created.id, tenantA)).toBeUndefined();
  });

  it('list orders by creation order', async () => {
    const repo = await build();
    const first = await repo.create({
      tenantId: tenantA,
      type: 'service',
      name: 'first',
      ownerId: owner,
    });
    const second = await repo.create({
      tenantId: tenantA,
      type: 'service',
      name: 'second',
      ownerId: owner,
    });
    const list = await repo.list(tenantA);
    expect(list.map((a) => a.id)).toEqual([first.id, second.id]);
  });
});
