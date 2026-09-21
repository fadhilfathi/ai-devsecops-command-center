import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildClusterRepository,
  buildPgClusterRepository,
  type ClusterRepository,
} from './cluster.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function pgRepo(): Promise<ClusterRepository> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return buildPgClusterRepository(db);
}

describe.each([
  ['in-memory', async () => buildClusterRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s cluster repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('creates and lists clusters scoped by tenant', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      name: 'prod-a',
      server: 'https://a.example.com',
      provider: 'eks',
      environment: 'prod',
      labels: { team: 'platform' },
    });
    await repo.create({
      tenantId: tenantB,
      name: 'prod-b',
      server: 'https://b.example.com',
      provider: 'gke',
    });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({
      name: 'prod-a',
      tenantId: tenantA,
      labels: { team: 'platform' },
    });

    const listB = await repo.list(tenantB);
    expect(listB).toHaveLength(1);
    expect(listB[0]?.name).toBe('prod-b');
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'c1',
      server: 'https://c1.example.com',
      provider: 'kind',
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('remove deletes only the tenant-owned cluster', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'c2',
      server: 'https://c2.example.com',
      provider: 'kind',
    });
    expect(await repo.remove(created.id, tenantB)).toBe(false);
    expect(await repo.remove(created.id, tenantA)).toBe(true);
    expect(await repo.findById(created.id, tenantA)).toBeUndefined();
  });

  it('getProviderIdForCluster routes fixture vs live', async () => {
    const repo = await build();
    const live = await repo.create({
      tenantId: tenantA,
      name: 'live',
      server: 'https://live.example.com',
      provider: 'eks',
    });
    const fixture = await repo.create({
      tenantId: tenantA,
      name: 'fixture',
      server: 'https://fixture.example.com',
      provider: 'fixture' as never,
    });
    expect(await repo.getProviderIdForCluster(live.id, tenantA)).toBe('live');
    expect(await repo.getProviderIdForCluster(fixture.id, tenantA)).toBe('fixture');
  });

  it('getConnection returns stored credentials', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'creds',
      server: 'https://creds.example.com',
      provider: 'eks',
      token: 'tok',
      caBundle: 'ca',
      insecureSkipVerify: true,
    });
    expect(await repo.getConnection(created.id, tenantA)).toEqual({
      server: 'https://creds.example.com',
      token: 'tok',
      caBundle: 'ca',
      insecureSkipVerify: true,
    });
  });
});
