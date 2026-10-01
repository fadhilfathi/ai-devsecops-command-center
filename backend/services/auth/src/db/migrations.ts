/**
 * Postgres schema migrations for auth-service (S12).
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration source
 * ships with the compiled `dist/` output with no extra copy step — see
 * `@aicc/shared/db`'s `migrate()`.
 *
 * The seed row is part of the migration on purpose: `POST /v1/auth/dev-login`
 * looks the user up by email and 404s on a miss, and that is the only login
 * path in the platform until real credential auth lands. Seeding here means a
 * freshly migrated database is immediately usable, and the migration only ever
 * runs once per database (tracked in `schema_migrations`).
 */
import type { Migration } from '@aicc/shared/db';

/** Must stay in sync with `buildUserRepository()`'s in-memory seed. */
export const SEED_PLATFORM_ADMIN_ID = '00000000-0000-4000-8000-000000000001';
export const SEED_PLATFORM_ADMIN_TENANT_ID = '00000000-0000-4000-8000-000000000000';
export const SEED_PLATFORM_ADMIN_EMAIL = 'admin@aicc.local';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_users',
    sql: `
      CREATE TABLE users (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        email text NOT NULL UNIQUE,
        display_name text NOT NULL,
        role text NOT NULL,
        active boolean NOT NULL DEFAULT true,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX users_tenant_id_idx ON users (tenant_id);

      INSERT INTO users (id, tenant_id, email, display_name, role, active)
      VALUES (
        '${SEED_PLATFORM_ADMIN_ID}',
        '${SEED_PLATFORM_ADMIN_TENANT_ID}',
        '${SEED_PLATFORM_ADMIN_EMAIL}',
        'Platform Admin',
        'platform_admin',
        true
      )
      ON CONFLICT (id) DO NOTHING;
    `,
  },
];
