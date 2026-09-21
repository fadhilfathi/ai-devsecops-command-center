import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { migrate, type Queryable } from './index.js';

describe('migrate', () => {
  it('applies migrations once, in order, and is idempotent on re-run', async () => {
    const db = new PGlite() as unknown as Queryable;
    await migrate(db, [
      { name: '001_users', sql: 'CREATE TABLE users (id text PRIMARY KEY)' },
      { name: '002_seed', sql: "INSERT INTO users (id) VALUES ('a')" },
    ]);
    // Re-running must not re-apply (would violate the primary key / re-insert).
    await migrate(db, [
      { name: '001_users', sql: 'CREATE TABLE users (id text PRIMARY KEY)' },
      { name: '002_seed', sql: "INSERT INTO users (id) VALUES ('a')" },
    ]);

    const { rows } = await db.query<{ id: string }>('SELECT id FROM users');
    expect(rows).toEqual([{ id: 'a' }]);

    const { rows: applied } = await db.query<{ name: string }>(
      'SELECT name FROM schema_migrations ORDER BY name',
    );
    expect(applied.map((r) => r.name)).toEqual(['001_users', '002_seed']);
  });

  it('rolls back a failing migration without recording it as applied', async () => {
    const db = new PGlite() as unknown as Queryable;
    await expect(migrate(db, [{ name: '001_bad', sql: 'NOT VALID SQL' }])).rejects.toThrow();

    const { rows } = await db.query<{ name: string }>('SELECT name FROM schema_migrations');
    expect(rows).toEqual([]);
  });
});
