/**
 * Minimal Postgres helpers shared across services.
 *
 * No ORM: services write plain SQL against `Queryable`, which both
 * `pg.Pool` (production) and `@electric-sql/pglite` (tests, no Docker
 * required) satisfy. Migrations are plain TS modules exporting SQL
 * strings so they ship with the compiled `dist/` output without any
 * extra copy step.
 */
import pg from 'pg';

export interface Queryable {
  query<R = unknown>(text: string, params?: unknown[]): Promise<{ rows: R[] }>;
}

export interface Migration {
  name: string;
  sql: string;
}

export function createPool(databaseUrl: string): pg.Pool {
  return new pg.Pool({ connectionString: databaseUrl });
}

/**
 * Applies unapplied migrations in order, each inside its own transaction.
 * A `pg.Pool` hands out a different connection per `query()`, so the whole
 * run is pinned to one checked-out client; a single-connection `Queryable`
 * (PGlite) is used as-is.
 */
export async function migrate(target: Queryable | pg.Pool, migrations: Migration[]): Promise<void> {
  const client = target instanceof pg.Pool ? await target.connect() : undefined;
  const db: Queryable = client ?? (target as Queryable);
  try {
    await runMigrations(db, migrations);
  } finally {
    client?.release();
  }
}

async function runMigrations(db: Queryable, migrations: Migration[]): Promise<void> {
  await db.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       name text PRIMARY KEY,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`,
  );
  const { rows } = await db.query<{ name: string }>('SELECT name FROM schema_migrations');
  const applied = new Set(rows.map((r) => r.name));

  for (const migration of migrations) {
    if (applied.has(migration.name)) continue;
    await db.query('BEGIN');
    try {
      // ponytail: naive `;` split — migrations must not embed a literal
      // semicolon inside a string/identifier. Fine for schema DDL; revisit
      // with a real SQL statement splitter if that ever changes.
      for (const statement of splitStatements(migration.sql)) {
        await db.query(statement);
      }
      await db.query('INSERT INTO schema_migrations (name) VALUES ($1)', [migration.name]);
      await db.query('COMMIT');
    } catch (err) {
      await db.query('ROLLBACK');
      throw err;
    }
  }
}

function splitStatements(sql: string): string[] {
  return sql
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
