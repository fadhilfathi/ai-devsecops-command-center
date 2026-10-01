import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildEvidenceRepository,
  buildPgEvidenceRepository,
  type EvidenceRepository,
} from './evidence.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<EvidenceRepository> {
  return buildPgEvidenceRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildEvidenceRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s evidence repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';
  const controlA = '33333333-3333-3333-3333-333333333333';
  const controlB = '44444444-4444-4444-4444-444444444444';
  const user = '00000000-0000-4000-8000-000000000001';

  it('creates and lists evidence scoped by tenant', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'screenshot',
      description: 'a',
      ref: 'blob://a',
      collectedBy: user,
    });
    await repo.create({
      tenantId: tenantB,
      controlId: controlA,
      kind: 'log',
      description: 'b',
      ref: 'blob://b',
      collectedBy: user,
    });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({ ref: 'blob://a', tenantId: tenantA });

    const listB = await repo.list(tenantB);
    expect(listB).toHaveLength(1);
    expect(listB[0]?.ref).toBe('blob://b');
  });

  it('filters by controlId within the tenant', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'config',
      description: 'first',
      ref: 'blob://1',
      collectedBy: user,
    });
    await repo.create({
      tenantId: tenantA,
      controlId: controlB,
      kind: 'attestation',
      description: 'second',
      ref: 'blob://2',
      collectedBy: user,
    });
    // Same controlId, other tenant — must not leak into tenant A's filter.
    await repo.create({
      tenantId: tenantB,
      controlId: controlA,
      kind: 'other',
      description: 'other-tenant',
      ref: 'blob://3',
      collectedBy: user,
    });

    const forControlA = await repo.list(tenantA, controlA);
    expect(forControlA).toHaveLength(1);
    expect(forControlA[0]?.ref).toBe('blob://1');

    expect(await repo.list(tenantA, '55555555-5555-5555-5555-555555555555')).toHaveLength(0);
    expect(await repo.list(tenantA)).toHaveLength(2);
  });

  it('preserves kind, description and collector', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'attestation',
      description: 'signed by auditor',
      ref: 'blob://att',
      collectedBy: user,
    });
    expect(created).toMatchObject({
      kind: 'attestation',
      description: 'signed by auditor',
      ref: 'blob://att',
      collectedBy: user,
      controlId: controlA,
    });
    const found = await repo.findById(created.id, tenantA);
    expect(found).toEqual(created);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'screenshot',
      description: 'c',
      ref: 'blob://c',
      collectedBy: user,
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('findByRef respects tenant isolation', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'log',
      description: 'd',
      ref: 'blob://shared',
      collectedBy: user,
    });

    expect(await repo.findByRef(tenantA, controlA, 'blob://shared')).toMatchObject({
      ref: 'blob://shared',
    });
    expect(await repo.findByRef(tenantB, controlA, 'blob://shared')).toBeUndefined();
    expect(await repo.findByRef(tenantA, controlB, 'blob://shared')).toBeUndefined();
    expect(await repo.findByRef(tenantA, controlA, 'blob://missing')).toBeUndefined();
  });

  it('list orders by collection order', async () => {
    const repo = await build();
    const first = await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'log',
      description: 'first',
      ref: 'blob://first',
      collectedBy: user,
    });
    const second = await repo.create({
      tenantId: tenantA,
      controlId: controlA,
      kind: 'log',
      description: 'second',
      ref: 'blob://second',
      collectedBy: user,
    });
    const list = await repo.list(tenantA, controlA);
    expect(list.map((e) => e.id)).toEqual([first.id, second.id]);
  });
});
