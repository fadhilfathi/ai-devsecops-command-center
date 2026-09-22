import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import { createCipherKeyring, parseKeyring, generateKey } from '@aicc/shared/crypto';
import {
  buildClusterRepository,
  buildPgClusterRepository,
  type ClusterRepository,
} from './cluster.repository.js';
import { MIGRATIONS, migrateCredentials, reencryptCredentials } from '../db/migrations.js';

const noopLogger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never;

const keyring = parseKeyring(`v1:${generateKey()}`);

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<ClusterRepository> {
  return buildPgClusterRepository(await newPglite());
}

async function pgRepoWithKeyring(): Promise<ClusterRepository> {
  return buildPgClusterRepository(await newPglite(), keyring);
}

describe.each([
  ['in-memory', async () => buildClusterRepository()],
  ['in-memory (encrypted)', async () => buildClusterRepository(keyring)],
  ['postgres (pglite)', pgRepo],
  ['postgres (pglite, encrypted)', pgRepoWithKeyring],
] as const)('%s cluster repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';
  const tenantB = '22222222-2222-2222-2222-222222222222';

  it('creates and lists clusters scoped by tenant', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      name: 'prod-a',
      server: 'https://a.example.com',
      provider: 'eks',
      environment: 'prod',
      labels: { team: 'platform' },
    });
    await repo.create({
      tenantId: tenantB,
      name: 'prod-b',
      server: 'https://b.example.com',
      provider: 'gke',
    });

    const listA = await repo.list(tenantA);
    expect(listA).toHaveLength(1);
    expect(listA[0]).toMatchObject({
      name: 'prod-a',
      tenantId: tenantA,
      labels: { team: 'platform' },
    });

    const listB = await repo.list(tenantB);
    expect(listB).toHaveLength(1);
    expect(listB[0]?.name).toBe('prod-b');
  });

  it('findById respects tenant isolation', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'c1',
      server: 'https://c1.example.com',
      provider: 'kind',
    });
    expect(await repo.findById(created.id, tenantA)).toMatchObject({ id: created.id });
    expect(await repo.findById(created.id, tenantB)).toBeUndefined();
  });

  it('remove deletes only the tenant-owned cluster', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'c2',
      server: 'https://c2.example.com',
      provider: 'kind',
    });
    expect(await repo.remove(created.id, tenantB)).toBe(false);
    expect(await repo.remove(created.id, tenantA)).toBe(true);
    expect(await repo.findById(created.id, tenantA)).toBeUndefined();
  });

  it('getProviderIdForCluster routes fixture vs live', async () => {
    const repo = await build();
    const live = await repo.create({
      tenantId: tenantA,
      name: 'live',
      server: 'https://live.example.com',
      provider: 'eks',
    });
    const fixture = await repo.create({
      tenantId: tenantA,
      name: 'fixture',
      server: 'https://fixture.example.com',
      provider: 'fixture' as never,
    });
    expect(await repo.getProviderIdForCluster(live.id, tenantA)).toBe('live');
    expect(await repo.getProviderIdForCluster(fixture.id, tenantA)).toBe('fixture');
  });

  it('getConnection returns stored credentials', async () => {
    const repo = await build();
    const created = await repo.create({
      tenantId: tenantA,
      name: 'creds',
      server: 'https://creds.example.com',
      provider: 'eks',
      token: 'tok',
      caBundle: 'ca',
      insecureSkipVerify: true,
    });
    expect(await repo.getConnection(created.id, tenantA)).toEqual({
      server: 'https://creds.example.com',
      token: 'tok',
      caBundle: 'ca',
      insecureSkipVerify: true,
    });
  });

  it('list/findById never expose credential fields', async () => {
    const repo = await build();
    await repo.create({
      tenantId: tenantA,
      name: 'creds2',
      server: 'https://creds2.example.com',
      provider: 'eks',
      token: 'super-secret-token',
      caBundle: 'ca-data',
    });
    const [listed] = await repo.list(tenantA);
    expect(listed).not.toHaveProperty('token');
    expect(listed).not.toHaveProperty('caBundle');
    expect(listed).not.toHaveProperty('_credentials');
    expect(JSON.stringify(listed)).not.toContain('super-secret-token');
    const found = await repo.findById(listed!.id, tenantA);
    expect(JSON.stringify(found)).not.toContain('super-secret-token');
  });
});

describe('credential encryption at rest (postgres)', () => {
  it('stores ciphertext, not the plaintext token, in the row', async () => {
    const db = await newPglite();
    const repo = buildPgClusterRepository(db, keyring);
    const created = await repo.create({
      tenantId: '11111111-1111-1111-1111-111111111111',
      name: 'enc-check',
      server: 'https://enc.example.com',
      provider: 'eks',
      token: 'plaintext-token-value',
      caBundle: 'plaintext-ca-value',
    });
    const { rows } = await db.query<{
      token: string | null;
      ca_bundle: string | null;
      token_enc: string | null;
      ca_bundle_enc: string | null;
      credential_key_id: string | null;
    }>(
      'SELECT token, ca_bundle, token_enc, ca_bundle_enc, credential_key_id FROM clusters WHERE id = $1',
      [created.id],
    );
    const row = rows[0]!;
    expect(row.token).toBeNull();
    expect(row.ca_bundle).toBeNull();
    expect(row.token_enc).not.toBeNull();
    expect(row.token_enc).not.toContain('plaintext-token-value');
    expect(row.ca_bundle_enc).not.toContain('plaintext-ca-value');
    expect(row.credential_key_id).toBe('v1');
  });

  it('re-encrypts a legacy plaintext row via migrateCredentials and it stays readable', async () => {
    const db = await newPglite();
    const plainRepo = buildPgClusterRepository(db); // no keyring: legacy plaintext write path
    const created = await plainRepo.create({
      tenantId: '11111111-1111-1111-1111-111111111111',
      name: 'legacy',
      server: 'https://legacy.example.com',
      provider: 'eks',
      token: 'legacy-token',
      caBundle: 'legacy-ca',
    });

    await migrateCredentials(db, keyring, noopLogger);

    const { rows } = await db.query<{ token: string | null; token_enc: string | null }>(
      'SELECT token, token_enc FROM clusters WHERE id = $1',
      [created.id],
    );
    expect(rows[0]!.token).toBeNull();
    expect(rows[0]!.token_enc).not.toBeNull();

    const encRepo = buildPgClusterRepository(db, keyring);
    expect(await encRepo.getConnection(created.id, '11111111-1111-1111-1111-111111111111')).toEqual(
      {
        server: 'https://legacy.example.com',
        token: 'legacy-token',
        caBundle: 'legacy-ca',
        insecureSkipVerify: false,
      },
    );

    // idempotent re-run
    await migrateCredentials(db, keyring, noopLogger);
    const { rows: after } = await db.query<{ token_enc: string }>(
      'SELECT token_enc FROM clusters WHERE id = $1',
      [created.id],
    );
    expect(after[0]!.token_enc).toBe(rows[0]!.token_enc);
  });
});

describe('no keyring configured (dev fallback)', () => {
  it('in-memory repository still works without a keyring', async () => {
    const repo = buildClusterRepository();
    const created = await repo.create({
      tenantId: '11111111-1111-1111-1111-111111111111',
      name: 'no-keyring',
      server: 'https://nk.example.com',
      provider: 'eks',
      token: 'tok',
    });
    expect(
      await repo.getConnection(created.id, '11111111-1111-1111-1111-111111111111'),
    ).toMatchObject({ token: 'tok' });
  });

  it('postgres repository still works without a keyring', async () => {
    const db = await newPglite();
    const repo = buildPgClusterRepository(db);
    const created = await repo.create({
      tenantId: '11111111-1111-1111-1111-111111111111',
      name: 'no-keyring-pg',
      server: 'https://nkpg.example.com',
      provider: 'eks',
      token: 'tok',
    });
    expect(
      await repo.getConnection(created.id, '11111111-1111-1111-1111-111111111111'),
    ).toMatchObject({ token: 'tok' });
  });
});

describe('credential substitution guard (postgres)', () => {
  it('throws when a keyring is configured but a row carries a legacy plaintext column with no ciphertext', async () => {
    const db = await newPglite();
    const tenantId = '11111111-1111-1111-1111-111111111111';
    // Simulate a row where `token` was written out-of-band (no write
    // path in this codebase produces this state): token_enc is null,
    // the legacy plaintext column is set, while a keyring is configured.
    await db.query(
      `INSERT INTO clusters (id, tenant_id, name, provider, environment, labels, server, token, insecure_skip_verify)
       VALUES ($1, $2, 'substituted', 'eks', 'dev', '{}', 'https://sub.example.com', 'substituted-plaintext-token', false)`,
      ['33333333-3333-3333-3333-333333333333', tenantId],
    );
    const repo = buildPgClusterRepository(db, keyring);
    await expect(
      repo.getConnection('33333333-3333-3333-3333-333333333333', tenantId),
    ).rejects.toThrow(/legacy plaintext credential column/);
  });
});

describe('key rotation (postgres)', () => {
  const tenantId = '11111111-1111-1111-1111-111111111111';

  it('reencryptCredentials moves rows onto the new active key and getConnection keeps returning the original values', async () => {
    const KEY_A = generateKey();
    const KEY_B = generateKey();
    const keyringA = createCipherKeyring({
      keys: { keyA: Buffer.from(KEY_A, 'base64') },
      activeKeyId: 'keyA',
    });
    const db = await newPglite();
    const repoA = buildPgClusterRepository(db, keyringA);
    const created = await repoA.create({
      tenantId,
      name: 'rotate-me',
      server: 'https://rotate.example.com',
      provider: 'eks',
      token: 'rotate-token',
      caBundle: 'rotate-ca',
    });

    const { rows: before } = await db.query<{ token_enc: string; credential_key_id: string }>(
      'SELECT token_enc, credential_key_id FROM clusters WHERE id = $1',
      [created.id],
    );
    expect(before[0]!.credential_key_id).toBe('keyA');

    const keyringAB = createCipherKeyring({
      keys: { keyA: Buffer.from(KEY_A, 'base64'), keyB: Buffer.from(KEY_B, 'base64') },
      activeKeyId: 'keyB',
    });
    await reencryptCredentials(db, keyringAB, noopLogger);

    const { rows: after } = await db.query<{ token_enc: string; credential_key_id: string }>(
      'SELECT token_enc, credential_key_id FROM clusters WHERE id = $1',
      [created.id],
    );
    expect(after[0]!.credential_key_id).toBe('keyB');
    expect(after[0]!.token_enc.split('.')[1]).toBe('keyB');
    expect(after[0]!.token_enc).not.toBe(before[0]!.token_enc);

    const repoAB = buildPgClusterRepository(db, keyringAB);
    expect(await repoAB.getConnection(created.id, tenantId)).toEqual({
      server: 'https://rotate.example.com',
      token: 'rotate-token',
      caBundle: 'rotate-ca',
      insecureSkipVerify: false,
    });

    // idempotent re-run: already on the active key, nothing changes
    await reencryptCredentials(db, keyringAB, noopLogger);
    const { rows: rerun } = await db.query<{ token_enc: string }>(
      'SELECT token_enc FROM clusters WHERE id = $1',
      [created.id],
    );
    expect(rerun[0]!.token_enc).toBe(after[0]!.token_enc);

    // dropping key A afterwards still decrypts (row is now under key B)
    const keyringBOnly = createCipherKeyring({
      keys: { keyB: Buffer.from(KEY_B, 'base64') },
      activeKeyId: 'keyB',
    });
    const repoBOnly = buildPgClusterRepository(db, keyringBOnly);
    expect(await repoBOnly.getConnection(created.id, tenantId)).toEqual({
      server: 'https://rotate.example.com',
      token: 'rotate-token',
      caBundle: 'rotate-ca',
      insecureSkipVerify: false,
    });
  });
});

describe('tamper detection (postgres)', () => {
  it('getConnection throws when token_enc is corrupted in the row', async () => {
    const db = await newPglite();
    const tenantId = '11111111-1111-1111-1111-111111111111';
    const repo = buildPgClusterRepository(db, keyring);
    const created = await repo.create({
      tenantId,
      name: 'tampered',
      server: 'https://tampered.example.com',
      provider: 'eks',
      token: 'tampered-token',
    });
    await db.query('UPDATE clusters SET token_enc = $2 WHERE id = $1', [
      created.id,
      'v1.v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAA',
    ]);
    await expect(repo.getConnection(created.id, tenantId)).rejects.toThrow();
  });
});
