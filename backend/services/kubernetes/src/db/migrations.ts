/**
 * Postgres schema migrations for the kubernetes-service.
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration
 * source ships with the compiled `dist/` output with no extra copy
 * step — see `@aicc/shared/db`'s `migrate()`.
 */
import type { Migration } from '@aicc/shared/db';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_clusters',
    sql: `
      CREATE TABLE clusters (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        name text NOT NULL,
        provider text NOT NULL,
        environment text NOT NULL DEFAULT 'dev',
        labels jsonb NOT NULL DEFAULT '{}'::jsonb,
        server text,
        token text,
        ca_bundle text,
        insecure_skip_verify boolean NOT NULL DEFAULT false,
        k8s_version text,
        region text,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX clusters_tenant_id_idx ON clusters (tenant_id);
    `,
  },
];
