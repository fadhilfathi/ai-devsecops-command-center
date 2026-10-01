/**
 * Postgres schema migrations for compliance-service (S12).
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration source
 * ships with the compiled `dist/` output with no extra copy step — see
 * `@aicc/shared/db`'s `migrate()`.
 *
 * No `frameworks` table: `FrameworkRepository` serves the fixed SUPPORTED
 * constant list (CIS/NIST/SOC2/ISO) with no per-tenant or mutable state,
 * so there is nothing to persist — see `repositories/framework.repository.ts`.
 */
import type { Migration } from '@aicc/shared/db';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_controls_evidence',
    sql: `
      CREATE TABLE controls (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        framework text NOT NULL,
        control_id text NOT NULL,
        title text NOT NULL,
        description text NOT NULL,
        status text NOT NULL DEFAULT 'manual_review',
        evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX controls_tenant_id_idx ON controls (tenant_id);
      CREATE INDEX controls_tenant_framework_idx ON controls (tenant_id, framework);

      CREATE TABLE evidence (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        control_id uuid NOT NULL,
        kind text NOT NULL,
        description text NOT NULL,
        ref text NOT NULL,
        collected_by uuid NOT NULL,
        collected_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX evidence_tenant_id_idx ON evidence (tenant_id);
      CREATE INDEX evidence_tenant_control_idx ON evidence (tenant_id, control_id);
      CREATE INDEX evidence_tenant_ref_idx ON evidence (tenant_id, control_id, ref);
    `,
  },
];
