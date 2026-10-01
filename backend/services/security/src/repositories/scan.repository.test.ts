import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildScanRepository,
  buildPgScanRepository,
  type ScanRepository,
} from './scan.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<ScanRepository> {
  return buildPgScanRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildScanRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s scan repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';
  const assetId = '33333333-3333-3333-3333-333333333333';

  it('creates and lists scans scoped by tenant', async () => {
    const repo = await build();
    await repo.create({ assetId, tenantId: tenantA, scanner: 'trivy' });
    await repo.create({ assetId, tenantId: tenantB, scanner: 'grype' });

    expect(await repo.list(tenantA)).toHaveLength(1);
    expect(await repo.list(tenantB)).toHaveLength(1);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({ assetId, tenantId: tenantA, scanner: 'trivy' });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('new scans start queued with zero findings', async () => {
    const repo = await build();
    const created = await repo.create({ assetId, tenantId: tenantA, scanner: 'trivy' });
    expect(created.status).toBe('queued');
    expect(created.findingsCount).toBe(0);
  });

  it('updateStatus transitions status and sets finishedAt for terminal states', async () => {
    const repo = await build();
    const created = await repo.create({ assetId, tenantId: tenantA, scanner: 'trivy' });
    const updated = await repo.updateStatus(created.id, created.tenantId, 'succeeded');
    expect(updated?.status).toBe('succeeded');
    expect(updated?.finishedAt).toBeDefined();

    const found = await repo.findById(created.id, tenantA);
    expect(found?.status).toBe('succeeded');
  });

  it('updateStatus on a running scan leaves finishedAt unset', async () => {
    const repo = await build();
    const created = await repo.create({ assetId, tenantId: tenantA, scanner: 'trivy' });
    const updated = await repo.updateStatus(created.id, created.tenantId, 'running');
    expect(updated?.status).toBe('running');
    expect(updated?.finishedAt).toBeUndefined();
  });

  it("updateStatus cannot touch another tenant's scan", async () => {
    const repo = await build();
    const created = await repo.create({ assetId, tenantId: tenantA, scanner: 'trivy' });
    expect(await repo.updateStatus(created.id, tenantB, 'failed')).toBeUndefined();
    expect((await repo.findById(created.id, tenantA))?.status).not.toBe('failed');
  });
});
