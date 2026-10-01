import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildSyncRepository,
  buildPgSyncRepository,
  type SyncRepository,
} from './sync.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<SyncRepository> {
  return buildPgSyncRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildSyncRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s sync repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';
  const integrationA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const integrationB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

  it('creates a queued record with no finish time or error', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'queued',
      metadata: {},
    });
    expect(created).toMatchObject({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'queued',
    });
    expect(created.finishedAt).toBeUndefined();
    expect(created.error).toBeUndefined();
    expect(new Date(created.startedAt).toString()).not.toBe('Invalid Date');
  });

  it('round-trips nested metadata through storage', async () => {
    const repo = await build();
    const metadata = {
      pr: { number: 12, labels: ['security', 'ci'] },
      counts: { files: 3 },
      flags: [true, false, null],
    };
    const created = await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'sbom_attach',
      status: 'running',
      metadata,
    });
    expect(created.metadata).toEqual(metadata);
    const listed = await repo.list(tenantA);
    expect(listed[0]?.metadata).toEqual(metadata);
  });

  it('lists only the calling tenant syncs', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'queued',
      metadata: {},
    });
    await repo.create({
      tenantId: tenantB,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'queued',
      metadata: {},
    });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]?.tenantId).toBe(tenantA);
    expect(await repo.list(tenantB)).toHaveLength(1);
  });

  it('filters by integrationId', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'queued',
      metadata: {},
    });
    await repo.create({
      tenantId: tenantA,
      integrationId: integrationB,
      kind: 'pr_scan',
      status: 'queued',
      metadata: {},
    });

    const filtered = await repo.list(tenantA, { integrationId: integrationB });
    expect(filtered).toHaveLength(1);
    expect(filtered[0]?.integrationId).toBe(integrationB);
  });

  it('filters by status', async () => {
    const repo = await build();
    const ok = await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'running',
      metadata: {},
    });
    await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'queued',
      metadata: {},
    });
    await repo.finish(ok.id, 'succeeded');

    const failedOnly = await repo.list(tenantA, { status: 'failed' });
    expect(failedOnly).toHaveLength(0);

    const succeeded = await repo.list(tenantA, { status: 'succeeded' });
    expect(succeeded).toHaveLength(1);
    expect(succeeded[0]?.id).toBe(ok.id);
  });

  it('applies integrationId and status filters together', async () => {
    const repo = await build();
    const target = await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'alerts',
      status: 'running',
      metadata: {},
    });
    await repo.finish(target.id, 'failed', 'boom');
    await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'alerts',
      status: 'running',
      metadata: {},
    });
    await repo.create({
      tenantId: tenantA,
      integrationId: integrationB,
      kind: 'alerts',
      status: 'running',
      metadata: {},
    });

    const failedForA = await repo.list(tenantA, {
      integrationId: integrationA,
      status: 'failed',
    });
    expect(failedForA).toHaveLength(1);
    expect(failedForA[0]).toMatchObject({ id: target.id, error: 'boom' });
  });

  it('finish sets status, finishedAt and error', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      integrationId: integrationA,
      kind: 'pr_scan',
      status: 'running',
      metadata: {},
    });

    const finished = await repo.finish(created.id, 'succeeded');
    expect(finished?.status).toBe('succeeded');
    expect(finished?.finishedAt).toBeDefined();
    expect(finished?.error).toBeUndefined();
    // The pre-existing integrationId/kind/metadata survive the update.
    expect(finished).toMatchObject({ integrationId: integrationA, kind: 'pr_scan' });
  });

  it('finish returns undefined for an unknown id', async () => {
    const repo = await build();
    expect(await repo.finish('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'succeeded')).toBeUndefined();
  });
});