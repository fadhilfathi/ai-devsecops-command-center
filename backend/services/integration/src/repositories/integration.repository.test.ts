import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildIntegrationRepository,
  buildPgIntegrationRepository,
  type IntegrationRepository,
} from './integration.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<IntegrationRepository> {
  return buildPgIntegrationRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildIntegrationRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s integration repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('creates and lists integrations scoped by tenant', async () => {
    const repo = await build();
    await repo.create({ tenantId: tenantA, provider: 'github', name: 'a1' });
    await repo.create({ tenantId: tenantB, provider: 'gitlab', name: 'b1' });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({ name: 'a1', tenantId: tenantA, provider: 'github' });

    const listB = await repo.list(tenantB);
    expect(listB).toHaveLength(1);
    expect(listB[0]?.name).toBe('b1');
  });

  it('defaults config to {} and enabled to true', async () => {
    const repo = await build();
    const created = await repo.create({ tenantId: tenantA, provider: 'slack', name: 'defaults' });
    expect(created.config).toEqual({});
    expect(created.enabled).toBe(true);
    expect(created.lastSyncAt).toBeUndefined();
  });

  it('honours an explicit enabled: false at create time', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      provider: 'jira',
      name: 'disabled',
      enabled: false,
    });
    expect(created.enabled).toBe(false);
    const found = await repo.findById(created.id, tenantA);
    expect(found?.enabled).toBe(false);
  });

  it('round-trips nested config through storage', async () => {
    const repo = await build();
    const config = {
      token: 'ghp_secret',
      org: 'aicc',
      nested: { deep: { value: 42 }, list: [1, 'two', { three: true }] },
      empty: [],
    };
    const created = await repo.create({
      tenantId: tenantA,
      provider: 'github',
      name: 'with-config',
      config,
    });
    expect(created.config).toEqual(config);
    const found = await repo.findById(created.id, tenantA);
    expect(found?.config).toEqual(config);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({ tenantId: tenantA, provider: 'github', name: 'c1' });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('setEnabled toggles only for the owning tenant', async () => {
    const repo = await build();
    const created = await repo.create({ tenantId: tenantA, provider: 'github', name: 'c2' });

    expect(await repo.setEnabled(created.id, tenantB, false)).toBeUndefined();
    expect((await repo.findById(created.id, tenantA))?.enabled).toBe(true);

    const updated = await repo.setEnabled(created.id, tenantA, false);
    expect(updated?.enabled).toBe(false);
    expect((await repo.findById(created.id, tenantA))?.enabled).toBe(false);
  });

  it('remove deletes only the tenant-owned integration', async () => {
    const repo = await build();
    const created = await repo.create({ tenantId: tenantA, provider: 'github', name: 'c3' });
    expect(await repo.remove(created.id, tenantB)).toBe(false);
    expect(await repo.remove(created.id, tenantA)).toBe(true);
    expect(await repo.findById(created.id, tenantA)).toBeUndefined();
  });

  it('recordSync stores lastSyncAt and bumps updatedAt', async () => {
    const repo = await build();
    const created = await repo.create({ tenantId: tenantA, provider: 'github', name: 'c4' });
    const at = '2026-01-02T03:04:05.000Z';

    expect(await repo.recordSync(created.id, tenantB, at)).toBeUndefined();

    const synced = await repo.recordSync(created.id, tenantA, at);
    expect(synced?.lastSyncAt).toBe(at);
    expect(synced?.updatedAt).toBe(at);
    expect((await repo.findById(created.id, tenantA))?.lastSyncAt).toBe(at);
  });

  it('list orders by creation order', async () => {
    const repo = await build();
    const first = await repo.create({ tenantId: tenantA, provider: 'github', name: 'first' });
    const second = await repo.create({ tenantId: tenantA, provider: 'github', name: 'second' });
    const list = await repo.list(tenantA);
    expect(list.map((i) => i.id)).toEqual([first.id, second.id]);
  });
});
