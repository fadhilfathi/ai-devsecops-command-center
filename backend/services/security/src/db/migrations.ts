/**
 * Postgres schema migrations for security-service (S11-4).
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration source
 * ships with the compiled `dist/` output with no extra copy step — see
 * `@aicc/shared/db`'s `migrate()`.
 */
import type { Migration } from '@aicc/shared/db';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_assets_scans_findings_sboms',
    sql: `
      CREATE TABLE assets (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        type text NOT NULL,
        name text NOT NULL,
        owner_id uuid NOT NULL,
        metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
        tags jsonb NOT NULL DEFAULT '[]'::jsonb,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX assets_tenant_id_idx ON assets (tenant_id);

      CREATE TABLE scans (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        asset_id uuid NOT NULL,
        status text NOT NULL,
        started_at timestamptz,
        finished_at timestamptz,
        findings_count integer NOT NULL DEFAULT 0,
        scanner text NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX scans_tenant_id_idx ON scans (tenant_id);

      CREATE TABLE findings (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        scan_id uuid NOT NULL,
        cve_id text,
        package_name text,
        package_version text,
        severity text NOT NULL,
        title text NOT NULL,
        description text NOT NULL,
        remediation text,
        status text NOT NULL DEFAULT 'open',
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX findings_tenant_id_idx ON findings (tenant_id);
      CREATE INDEX findings_tenant_severity_idx ON findings (tenant_id, severity);
      CREATE INDEX findings_tenant_status_idx ON findings (tenant_id, status);

      CREATE TABLE sboms (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        asset_id uuid NOT NULL,
        format text NOT NULL,
        document jsonb NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX sboms_tenant_id_idx ON sboms (tenant_id);
      CREATE INDEX sboms_tenant_asset_idx ON sboms (tenant_id, asset_id);

      CREATE TABLE sbom_components (
        tenant_id uuid NOT NULL,
        sbom_id uuid NOT NULL,
        asset_id uuid NOT NULL,
        component_id text NOT NULL,
        name text NOT NULL,
        version text NOT NULL,
        purl text NOT NULL,
        license text NOT NULL,
        supplier text,
        ecosystem text NOT NULL,
        depth integer NOT NULL,
        PRIMARY KEY (sbom_id, component_id)
      );
      CREATE INDEX sbom_components_tenant_sbom_idx ON sbom_components (tenant_id, sbom_id);

      CREATE TABLE sbom_edges (
        tenant_id uuid NOT NULL,
        sbom_id uuid NOT NULL,
        source text NOT NULL,
        target text NOT NULL,
        PRIMARY KEY (sbom_id, source, target)
      );
      CREATE INDEX sbom_edges_tenant_sbom_idx ON sbom_edges (tenant_id, sbom_id);
    `,
  },
];
