import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from '@aicc/shared/db';
import {
  buildPgUserRepository,
  buildUserRepository,
  type UserRepository,
} from './user.repository.js';
import { MIGRATIONS } from '../db/migrations.js';
import { buildServer } from '../index.js';

async function newPglite(): Promise<Queryable> {
  const db = new PGlite() as unknown as Queryable;
  await migrate(db, MIGRATIONS);
  return db;
}

async function pgRepo(): Promise<UserRepository> {
  return buildPgUserRepository(await newPglite());
}

describe.each([
  ['in-memory', async () => buildUserRepository()],
  ['postgres (pglite)', pgRepo],
] as const)('%s user repository', (_label, build) => {
  const tenantA = '11111111-1111-1111-1111-111111111111';

  it('seeds the platform admin that dev-login looks up by email', async () => {
    const repo = await build();
    const seeded = await repo.findByEmail('admin@aicc.local');
    expect(seeded).toMatchObject({
      id: '00000000-0000-4000-8000-000000000001',
      tenantId: '00000000-0000-4000-8000-000000000000',
      displayName: 'Platform Admin',
      role: 'platform_admin',
      active: true,
    });
    expect(seeded?.createdAt).toBeTruthy();
    expect(seeded?.updatedAt).toBeTruthy();
  });

  it('finds the seeded user by id as well as by email', async () => {
    const repo = await build();
    const byEmail = await repo.findByEmail('admin@aicc.local');
    const byId = await repo.findById('00000000-0000-4000-8000-000000000001');
    expect(byId?.email).toBe(byEmail?.email);
  });

  it('returns undefined for an unknown email', async () => {
    const repo = await build();
    expect(await repo.findByEmail('nobody@aicc.local')).toBeUndefined();
  });

  it('creates an active user and finds it by email', async () => {
    const repo = await build();
    const created = await repo.create({
      email: 'dana@aicc.local',
      displayName: 'Dana Analyst',
      role: 'security_analyst',
      tenantId: tenantA,
    });
    expect(created).toMatchObject({
      email: 'dana@aicc.local',
      displayName: 'Dana Analyst',
      role: 'security_analyst',
      tenantId: tenantA,
      active: true,
    });
    expect(created.id).toMatch(/^[0-9a-f-]{36}$/);
    expect((await repo.findByEmail('dana@aicc.local'))?.id).toBe(created.id);
    expect((await repo.findById(created.id))?.displayName).toBe('Dana Analyst');
  });

  it('lists the seed plus every created user', async () => {
    const repo = await build();
    await repo.create({
      email: 'erin@aicc.local',
      displayName: 'Erin',
      role: 'viewer',
      tenantId: tenantA,
    });
    const emails = (await repo.list()).map((u) => u.email);
    expect(emails).toContain('admin@aicc.local');
    expect(emails).toContain('erin@aicc.local');
  });

  it('deactivates and reactivates a user', async () => {
    const repo = await build();
    const target = await repo.findByEmail('admin@aicc.local');
    const deactivated = await repo.setActive(target!.id, false);
    expect(deactivated?.active).toBe(false);
    expect((await repo.findById(target!.id))?.active).toBe(false);

    const reactivated = await repo.setActive(target!.id, true);
    expect(reactivated?.active).toBe(true);
    expect((await repo.findByEmail('admin@aicc.local'))?.active).toBe(true);
  });

  it('setActive on an unknown id returns undefined', async () => {
    const repo = await build();
    expect(await repo.setActive('99999999-9999-4999-8999-999999999999', false)).toBeUndefined();
  });
});

describe('postgres schema constraints', () => {
  it('rejects a duplicate email at the database level', async () => {
    const repo = buildPgUserRepository(await newPglite());
    await repo.create({
      email: 'dup@aicc.local',
      displayName: 'First',
      role: 'developer',
      tenantId: '11111111-1111-1111-1111-111111111111',
    });
    await expect(
      repo.create({
        email: 'dup@aicc.local',
        displayName: 'Second',
        role: 'developer',
        tenantId: '11111111-1111-1111-1111-111111111111',
      }),
    ).rejects.toThrow();
  });
});

describe('postgres dev-login against a fresh database', () => {
  it('issues a token for the seeded platform admin', async () => {
    const db = await newPglite();
    const server = await buildServer({ users: buildPgUserRepository(db) });
    const res = await server.inject({
      method: 'POST',
      url: '/v1/auth/dev-login',
      payload: { email: 'admin@aicc.local' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      user: { id: '00000000-0000-4000-8000-000000000001', role: 'platform_admin' },
      accessToken: expect.any(String),
      refreshToken: expect.any(String),
    });
    await server.close();
  });

  it('404s an unknown email rather than issuing a token', async () => {
    const db = await newPglite();
    const server = await buildServer({ users: buildPgUserRepository(db) });
    const res = await server.inject({
      method: 'POST',
      url: '/v1/auth/dev-login',
      payload: { email: 'nobody@aicc.local' },
    });
    expect(res.statusCode).toBe(404);
    await server.close();
  });
});
