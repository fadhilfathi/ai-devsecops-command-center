import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildSbomRepository,
  buildPgSbomRepository,
  type SbomRepository,
} from './sbom.repository.js';
import { MIGRATIONS } from '../db/migrations.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<SbomRepository> {
  return buildPgSbomRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildSbomRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s sbom repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';
  const assetId = '33333333-3333-3333-3333-333333333333';

  it('creates and lists sboms scoped by tenant, filterable by assetId', async () => {
    const repo = await build();
    const s1 = await repo.create({ tenantId: tenantA, assetId, format: 'cyclonedx', document: {} });
    await repo.create({
      tenantId: tenantA,
      assetId: '44444444-4444-4444-4444-444444444444',
      format: 'cyclonedx',
      document: {},
    });
    await repo.create({ tenantId: tenantB, assetId, format: 'spdx', document: {} });

    expect(await repo.list(tenantA)).toHaveLength(2);
    expect(await repo.list(tenantA, assetId)).toEqual([s1]);
    expect(await repo.list(tenantB)).toHaveLength(1);
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      assetId,
      format: 'cyclonedx',
      document: { hello: 'world' },
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({
      document: { hello: 'world' },
    });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('replaceComponents stores components and edges, scoped by tenant/sbom', async () => {
    const repo = await build();
    const sbom = await repo.create({
      tenantId: tenantA,
      assetId,
      format: 'cyclonedx',
      document: {},
    });
    await repo.replaceComponents(
      tenantA,
      sbom.id,
      assetId,
      [
        {
          id: 'lodash@4.17.20',
          name: 'lodash',
          version: '4.17.20',
          purl: 'pkg:npm/lodash@4.17.20',
          license: 'MIT',
          ecosystem: 'npm',
          depth: 1,
        },
      ],
      [{ source: 'root', target: 'lodash@4.17.20' }],
    );

    const components = await repo.listComponents(tenantA, { sbomId: sbom.id });
    expect(components).toHaveLength(1);
    expect(components[0]).toMatchObject({ name: 'lodash', tenantId: tenantA, sbomId: sbom.id });

    const edges = await repo.listEdges(tenantA, { sbomId: sbom.id });
    expect(edges).toEqual([
      { tenantId: tenantA, sbomId: sbom.id, source: 'root', target: 'lodash@4.17.20' },
    ]);

    expect(await repo.listComponents(tenantB, { sbomId: sbom.id })).toHaveLength(0);
  });

  it('replaceComponents overwrites the prior index (no orphans on re-ingest)', async () => {
    const repo = await build();
    const sbom = await repo.create({
      tenantId: tenantA,
      assetId,
      format: 'cyclonedx',
      document: {},
    });
    await repo.replaceComponents(
      tenantA,
      sbom.id,
      assetId,
      [
        {
          id: 'a',
          name: 'a',
          version: '1',
          purl: 'pkg:npm/a@1',
          license: 'MIT',
          ecosystem: 'npm',
          depth: 0,
        },
      ],
      [],
    );
    await repo.replaceComponents(
      tenantA,
      sbom.id,
      assetId,
      [
        {
          id: 'b',
          name: 'b',
          version: '1',
          purl: 'pkg:npm/b@1',
          license: 'MIT',
          ecosystem: 'npm',
          depth: 0,
        },
      ],
      [],
    );

    const components = await repo.listComponents(tenantA, { sbomId: sbom.id });
    expect(components.map((c) => c.id)).toEqual(['b']);
  });

  it("replaceComponents rejects writes against another tenant's sbom", async () => {
    const repo = await build();
    const sbom = await repo.create({
      tenantId: tenantA,
      assetId,
      format: 'cyclonedx',
      document: {},
    });
    await expect(repo.replaceComponents(tenantB, sbom.id, assetId, [], [])).rejects.toThrow(
      /not found for tenant/,
    );
  });
});
