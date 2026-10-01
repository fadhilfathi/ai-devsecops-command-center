/**
 * Postgres schema migrations for integration-service (S12).
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration source
 * ships with the compiled `dist/` output with no extra copy step — see
 * `@aicc/shared/db`'s `migrate()`.
 */
import type { Migration } from '@aicc/shared/db';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_integrations_syncs',
    sql: `
      CREATE TABLE integrations (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        provider text NOT NULL,
        name text NOT NULL,
        config jsonb NOT NULL DEFAULT '{}'::jsonb,
        enabled boolean NOT NULL DEFAULT true,
        last_sync_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX integrations_tenant_id_idx ON integrations (tenant_id);

      CREATE TABLE syncs (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        integration_id uuid NOT NULL,
        kind text NOT NULL,
        status text NOT NULL,
        started_at timestamptz NOT NULL DEFAULT now(),
        finished_at timestamptz,
        error text,
        metadata jsonb NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE INDEX syncs_tenant_id_idx ON syncs (tenant_id);
      CREATE INDEX syncs_integration_id_idx ON syncs (integration_id);
      CREATE INDEX syncs_tenant_status_idx ON syncs (tenant_id, status);
    `,
  },
];
