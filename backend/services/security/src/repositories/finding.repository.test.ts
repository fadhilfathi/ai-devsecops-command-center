import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildFindingRepository,
  buildPgFindingRepository,
  type FindingRepository,
} from './finding.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<FindingRepository> {
  return buildPgFindingRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildFindingRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s finding repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';
  const scanId = '33333333-3333-3333-3333-333333333333';

  it('creates and lists findings scoped by tenant', async () => {
    const repo = await build();
    await repo.create({
      scanId,
      tenantId: tenantA,
      severity: 'high',
      title: 'a',
      description: 'a-desc',
    });
    await repo.create({
      scanId,
      tenantId: tenantB,
      severity: 'low',
      title: 'b',
      description: 'b-desc',
    });

    expect(await repo.list(tenantA)).toHaveLength(1);
    expect(await repo.list(tenantB)).toHaveLength(1);
  });

  it('filters by severity and status', async () => {
    const repo = await build();
    const high = await repo.create({
      scanId,
      tenantId: tenantA,
      severity: 'high',
      title: 'high-finding',
      description: 'desc',
    });
    await repo.create({
      scanId,
      tenantId: tenantA,
      severity: 'low',
      title: 'low-finding',
      description: 'desc',
    });
    await repo.updateStatus(high.id, tenantA, 'resolved');

    const highOnly = await repo.list(tenantA, { severity: 'high' });
    expect(highOnly).toHaveLength(1);
    expect(highOnly[0]?.title).toBe('high-finding');

    const resolvedOnly = await repo.list(tenantA, { status: 'resolved' });
    expect(resolvedOnly).toHaveLength(1);
    expect(resolvedOnly[0]?.id).toBe(high.id);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      scanId,
      tenantId: tenantA,
      severity: 'medium',
      title: 'c',
      description: 'c-desc',
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('updateStatus is tenant-scoped', async () => {
    const repo = await build();
    const created = await repo.create({
      scanId,
      tenantId: tenantA,
      severity: 'medium',
      title: 'd',
      description: 'd-desc',
    });
    expect(await repo.updateStatus(created.id, tenantB, 'resolved')).toBeUndefined();
    expect(await repo.updateStatus(created.id, tenantA, 'resolved')).toMatchObject({
      status: 'resolved',
    });
  });

  it('new findings default to open status', async () => {
    const repo = await build();
    const created = await repo.create({
      scanId,
      tenantId: tenantA,
      severity: 'critical',
      title: 'e',
      description: 'e-desc',
    });
    expect(created.status).toBe('open');
  });
});
