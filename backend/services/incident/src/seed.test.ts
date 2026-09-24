import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildIncidentRepository,
  buildPgIncidentRepository,
} from './repositories/incident.repository.js';
import {
  buildRunbookRepository,
  buildPgRunbookRepository,
} from './repositories/runbook.repository.js';
import { MIGRATIONS } from './db/migrations.js';
import { seedDemoData } from './seed.js';

const TENANT = '00000000-0000-4000-8000-000000000000';

async function pgRepos() {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return { incidents: buildPgIncidentRepository(db), runbooks: buildPgRunbookRepository(db) };
}

describe.each([
  [
    'in-memory',
    async () => ({ incidents: buildIncidentRepository(), runbooks: buildRunbookRepository() }),
  ],
  ['postgres (pglite)', pgRepos],
] as const)('%s seedDemoData', (_label, build) => {
  it('is idempotent — seeding twice does not duplicate rows', async () => {
    const repos = await build();

    await seedDemoData(repos, TENANT);
    const first = await repos.incidents.list(TENANT);
    expect(first.length).toBeGreaterThan(0);

    await seedDemoData(repos, TENANT);
    const second = await repos.incidents.list(TENANT);
    expect(second.length).toBe(first.length);
  });

  it('leaves the tenant empty when never called', async () => {
    const repos = await build();
    expect(await repos.incidents.list(TENANT)).toEqual([]);
  });
});
