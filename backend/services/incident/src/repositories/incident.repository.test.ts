import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildIncidentRepository,
  buildPgIncidentRepository,
  type IncidentRepository,
} from './incident.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function pgRepo(): Promise<IncidentRepository> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return buildPgIncidentRepository(db);
}

describe.each([
  ['in-memory', async () => buildIncidentRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s incident repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('creates incidents in open status and lists them scoped by tenant', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      title: 'CVE in prod',
      description: 'critical CVE detected',
      severity: 'critical',
    });
    expect(created.status).toBe('open');

    await repo.create({
      tenantId: tenantB,
      title: 'other tenant',
      description: 'x',
      severity: 'low',
    });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]?.id).toBe(created.id);
  });

  it('filters by status and severity', async () => {
    const repo = await build();
    const a = await repo.create({
      tenantId: tenantA,
      title: 'a',
      description: 'd',
      severity: 'high',
    });
    const b = await repo.create({
      tenantId: tenantA,
      title: 'b',
      description: 'd',
      severity: 'low',
    });
    await repo.update(a.id, tenantA, { status: 'resolved' });

    expect((await repo.list(tenantA, { status: 'open' })).map((i) => i.id)).toEqual([b.id]);
    expect((await repo.list(tenantA, { severity: 'low' })).map((i) => i.id)).toEqual([b.id]);
  });

  it('findById and update respect tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      title: 't',
      description: 'd',
      severity: 'medium',
    });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
    expect(await repo.update(created.id, tenantB, { status: 'closed' })).toBeUndefined();

    const updated = await repo.update(created.id, tenantA, { status: 'acknowledged' });
    expect(updated?.status).toBe('acknowledged');
    expect((await repo.findById(created.id, tenantA))?.status).toBe('acknowledged');
  });

  it('persists relatedFindingIds and runbookId', async () => {
    const repo = await build();
    const findingId = '33333333-3333-3333-3333-333333333333';
    const runbookId = '44444444-4444-4444-4444-444444444444';
    const created = await repo.create({
      tenantId: tenantA,
      title: 't',
      description: 'd',
      severity: 'medium',
      relatedFindingIds: [findingId],
      runbookId,
    });
    const found = await repo.findById(created.id, tenantA);
    expect(found?.relatedFindingIds).toEqual([findingId]);
    expect(found?.runbookId).toBe(runbookId);
  });
});
