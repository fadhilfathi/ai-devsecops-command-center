import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildChainRepository,
  buildPgChainRepository,
  type ChainRepository,
} from './chain.repository.js';
import { MIGRATIONS } from '../db/migrations.js';
import type { IncidentChain, CorrelationEdge } from './correlation-engine.js';

async function pgRepo(): Promise<ChainRepository> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return buildPgChainRepository(db);
}

function makeChain(tenantId: string): { chain: IncidentChain; edges: CorrelationEdge[] } {
  const edges: CorrelationEdge[] = [
    {
      id: 'e1',
      source: 'evt-1',
      target: 'evt-2',
      kind: 'caused_by',
      weight: 2,
      rationale: 'security.finding -> cicd.build.failed',
    },
  ];
  const chain: IncidentChain = {
    id: crypto.randomUUID(),
    tenantId,
    rootEventId: 'evt-1',
    eventIds: ['evt-1', 'evt-2'],
    edges,
    severity: 'critical',
    title: 'Incident: CVE-1234',
    summary: 'summary text',
    createdAt: new Date().toISOString(),
  };
  return { chain, edges };
}

describe.each([
  ['in-memory', async () => buildChainRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s chain repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('adds and lists chains scoped by tenant', async () => {
    const repo = await build();
    const { chain, edges } = makeChain(tenantA);
    await repo.add(chain, edges);
    await repo.add(makeChain(tenantB).chain, makeChain(tenantB).edges);

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({ id: chain.id, title: chain.title, eventIds: chain.eventIds });
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const { chain, edges } = makeChain(tenantA);
    await repo.add(chain, edges);
    expect(await repo.findById(chain.id, tenantB)).toBeUndefined();
    expect(await repo.findById(chain.id, tenantA)).toMatchObject({ id: chain.id });
  });

  it('edgesFor returns the edges recorded for the tenant', async () => {
    const repo = await build();
    const { chain, edges } = makeChain(tenantA);
    await repo.add(chain, edges);
    const found = await repo.edgesFor(tenantA);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ source: 'evt-1', target: 'evt-2', kind: 'caused_by' });
    expect(await repo.edgesFor(tenantB)).toHaveLength(0);
  });
});
