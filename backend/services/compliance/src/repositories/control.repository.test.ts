import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildControlRepository,
  buildPgControlRepository,
  type ControlRepository,
} from './control.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<ControlRepository> {
  return buildPgControlRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildControlRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s control repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('creates and lists controls scoped by tenant', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '4.1',
      title: 'a1',
      description: 'a-desc',
    });
    await repo.create({
      tenantId: tenantB,
      framework: 'soc2',
      controlId: 'CC6.1',
      title: 'b1',
      description: 'b-desc',
    });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({ title: 'a1', tenantId: tenantA });

    const listB = await repo.list(tenantB);
    expect(listB).toHaveLength(1);
    expect(listB[0]?.title).toBe('b1');
  });

  it('filters by framework within the tenant', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '4.1',
      title: 'cis',
      description: 'desc',
    });
    await repo.create({
      tenantId: tenantA,
      framework: 'nist_800_53',
      controlId: 'AC-2',
      title: 'nist',
      description: 'desc',
    });
    // Same framework id, other tenant — must not leak into tenant A's filter.
    await repo.create({
      tenantId: tenantB,
      framework: 'cis_v8',
      controlId: '4.2',
      title: 'other-tenant',
      description: 'desc',
    });

    const cisOnly = await repo.list(tenantA, { framework: 'cis_v8' });
    expect(cisOnly).toHaveLength(1);
    expect(cisOnly[0]?.title).toBe('cis');

    expect(await repo.list(tenantA, { framework: 'soc2' })).toHaveLength(0);
    expect(await repo.list(tenantA)).toHaveLength(2);
  });

  it('new controls default to manual_review with no evidence', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'iso_27001',
      controlId: 'A.5.1',
      title: 'policies',
      description: 'desc',
    });
    expect(created.status).toBe('manual_review');
    expect(created.evidenceRefs).toEqual([]);
  });

  it('create preserves supplied evidence refs', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'soc2',
      controlId: 'CC7.2',
      title: 'monitoring',
      description: 'desc',
      evidenceRefs: ['blob://a', 'blob://b'],
    });
    expect(created.evidenceRefs).toEqual(['blob://a', 'blob://b']);
    const found = await repo.findById(created.id, tenantA);
    expect(found?.evidenceRefs).toEqual(['blob://a', 'blob://b']);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '4.1',
      title: 'c1',
      description: 'c-desc',
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('updateStatus is tenant-scoped', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '4.1',
      title: 'd',
      description: 'd-desc',
    });
    expect(await repo.updateStatus(created.id, tenantB, 'pass')).toBeUndefined();
    // The rejected cross-tenant write must not have landed.
    expect((await repo.findById(created.id, tenantA))?.status).toBe('manual_review');

    const updated = await repo.updateStatus(created.id, tenantA, 'pass');
    expect(updated).toMatchObject({ id: created.id, status: 'pass' });
    expect((await repo.findById(created.id, tenantA))?.status).toBe('pass');
  });

  it('updateStatus bumps updatedAt', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'soc2',
      controlId: 'CC6.1',
      title: 'e',
      description: 'e-desc',
    });
    const updated = await repo.updateStatus(created.id, tenantA, 'fail');
    expect(updated).toBeDefined();
    expect(new Date(updated!.updatedAt).getTime()).toBeGreaterThanOrEqual(
      new Date(created.updatedAt).getTime(),
    );
  });

  it('addEvidence appends refs and is idempotent', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'soc2',
      controlId: 'CC6.1',
      title: 'f',
      description: 'f-desc',
      evidenceRefs: ['blob://a'],
    });

    const afterFirst = await repo.addEvidence(created.id, tenantA, 'blob://b');
    expect(afterFirst?.evidenceRefs).toEqual(['blob://a', 'blob://b']);

    const afterDup = await repo.addEvidence(created.id, tenantA, 'blob://b');
    expect(afterDup?.evidenceRefs).toEqual(['blob://a', 'blob://b']);
    expect((await repo.findById(created.id, tenantA))?.evidenceRefs).toEqual([
      'blob://a',
      'blob://b',
    ]);
  });

  it('addEvidence is tenant-scoped', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '4.1',
      title: 'g',
      description: 'g-desc',
    });
    expect(await repo.addEvidence(created.id, tenantB, 'blob://x')).toBeUndefined();
    expect((await repo.findById(created.id, tenantA))?.evidenceRefs).toEqual([]);
  });

  it('list orders by creation order', async () => {
    const repo = await build();
    const first = await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '1',
      title: 'first',
      description: 'desc',
    });
    const second = await repo.create({
      tenantId: tenantA,
      framework: 'cis_v8',
      controlId: '2',
      title: 'second',
      description: 'desc',
    });
    const list = await repo.list(tenantA);
    expect(list.map((c) => c.id)).toEqual([first.id, second.id]);
  });
});
