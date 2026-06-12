/**
 * Cross-cutting primitive types shared across all AICC domain models.
 *
 * Sprint 2: this file is created as part of the F-1 build-breaking bug fix
 * surfaced by ComplianceOfficer (`VulnSeverity` + `VulnKind` ask). The four
 * types below were previously referenced via `import ... from './common.js'`
 * in `domain.ts`, but the file did not exist on disk — the build only
 * worked when consumers imported from the pre-compiled `dist/` artefacts.
 * This file is the canonical source of truth.
 *
 * Conventions:
 * - `UUID` is a string (UUID v4 in practice, but typed as a string for
 *   interop with Python and JSON Schema).
 * - `Severity` is the canonical severity enum used by findings, incidents,
 *   vulnerabilities, and risks. Zod mirrors this in
 *   `backend/models/security/vulnerability.model.ts: SeveritySchema`.
 * - `BaseEntity` is the soft contract for any persisted entity.
 * - `TenantScoped` is the multi-tenancy isolation invariant — every
 *   persisted entity MUST carry a `tenantId`. See
 *   `docs/architecture/security-model.md` §3.4.
 */
export type UUID = string;

/** ISO-8601 timestamp string with timezone offset (e.g. `2026-06-12T10:30:00Z`). */
export type ISOTimestamp = string;

export type Severity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'unknown';

export interface BaseEntity {
  id: UUID;
  createdAt: ISOTimestamp;
  updatedAt: ISOTimestamp;
}

/**
 * Marker interface for entities that are tenant-isolated.
 *
 * **Invariant**: `tenantId` is stamped at the security-service :4003
 * boundary from the authenticated JWT — it is NEVER trusted from upstream
 * feeds (NVD, GHSA, OSV, Trivy, etc.). See the S2.10 GitOps wire format
 * spec and the multi-tenant isolation rules in
 * `docs/architecture/security-model.md` §3.4.
 */
export interface TenantScoped {
  tenantId: string;
}
