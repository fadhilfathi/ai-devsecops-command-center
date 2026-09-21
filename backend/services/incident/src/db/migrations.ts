/**
 * Postgres schema migrations for the incident-service.
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration
 * source ships with the compiled `dist/` output with no extra copy
 * step — see `@aicc/shared/db`'s `migrate()`.
 */
import type { Migration } from '@aicc/shared/db';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_incidents_and_runbooks',
    sql: `
      CREATE TABLE runbooks (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        name text NOT NULL,
        description text NOT NULL,
        steps jsonb NOT NULL DEFAULT '[]'::jsonb,
        triggers jsonb NOT NULL DEFAULT '[]'::jsonb,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX runbooks_tenant_id_idx ON runbooks (tenant_id);

      CREATE TABLE incidents (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        title text NOT NULL,
        description text NOT NULL,
        severity text NOT NULL,
        status text NOT NULL DEFAULT 'open',
        assignee_id uuid,
        related_finding_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
        runbook_id uuid,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX incidents_tenant_id_idx ON incidents (tenant_id);
      CREATE INDEX incidents_tenant_status_idx ON incidents (tenant_id, status);
      CREATE INDEX incidents_tenant_severity_idx ON incidents (tenant_id, severity);
    `,
  },
  {
    name: '002_chains_and_edges',
    sql: `
      CREATE TABLE incident_chains (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        root_event_id text NOT NULL,
        event_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
        edges jsonb NOT NULL DEFAULT '[]'::jsonb,
        severity text NOT NULL,
        title text NOT NULL,
        summary text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX incident_chains_tenant_id_idx ON incident_chains (tenant_id);

      CREATE TABLE correlation_edges (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        source text NOT NULL,
        target text NOT NULL,
        kind text NOT NULL,
        weight double precision NOT NULL,
        rationale text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX correlation_edges_tenant_id_idx ON correlation_edges (tenant_id);
    `,
  },
];
