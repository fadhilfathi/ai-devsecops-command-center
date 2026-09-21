import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildRunbookRepository,
  buildPgRunbookRepository,
  type RunbookRepository,
} from './runbook.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function pgRepo(): Promise<RunbookRepository> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return buildPgRunbookRepository(db);
}

describe.each([
  ['in-memory', async () => buildRunbookRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s runbook repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('creates and lists runbooks with nested steps', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'Rotate credentials',
      description: 'x',
      steps: [{ order: 1, title: 'Revoke', detail: 'revoke the token' }],
      triggers: ['leaked-credential'],
    });
    expect(created.steps).toEqual([{ order: 1, title: 'Revoke', detail: 'revoke the token' }]);

    await repo.create({
      tenantId: tenantB,
      name: 'other',
      description: 'd',
      steps: [],
      triggers: [],
    });
    expect(await repo.list(tenantA)).toHaveLength(1);
  });

  it('findById and remove respect tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'r',
      description: 'd',
      steps: [],
      triggers: [],
    });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
    expect(await repo.remove(created.id, tenantB)).toBe(false);
    expect(await repo.remove(created.id, tenantA)).toBe(true);
    expect(await repo.findById(created.id, tenantA)).toBeUndefined();
  });
});
