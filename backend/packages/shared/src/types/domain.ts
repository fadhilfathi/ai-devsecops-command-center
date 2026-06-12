/**
 * Domain models for the AI-DevSecOps Command Center.
 *
 * These are intentionally simple for the Sprint 1 skeleton — they will
 * evolve as the SecurityArchitect and ComplianceOfficer agents finalize
 * their respective designs.
 */

import type { BaseEntity, Severity, TenantScoped, UUID } from './common.js';
import { z } from 'zod';
import { VulnerabilityKindSchema } from '@aicc/models/security/vulnerability.model.js';

export type UserRole =
  | 'platform_admin'
  | 'security_analyst'
  | 'compliance_officer'
  | 'developer'
  | 'viewer';

export interface User extends BaseEntity, TenantScoped {
  email: string;
  displayName: string;
  role: UserRole;
  active: boolean;
}

export type AssetType = 'repository' | 'service' | 'container' | 'vm' | 'saas';

export interface Asset extends BaseEntity, TenantScoped {
  type: AssetType;
  name: string;
  ownerId: UUID;
  metadata: Record<string, unknown>;
  tags: string[];
}

export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';

export interface SecurityScan extends BaseEntity, TenantScoped {
  assetId: UUID;
  status: ScanStatus;
  startedAt?: string;
  finishedAt?: string;
  findingsCount: number;
  scanner: string;
}

export type FindingSeverity = Severity;

/**
 * Shared `VulnSeverity` re-export. The canonical source is `Severity` in
 * `./common.ts`; this alias exists so consumer code (Python agents,
 * compliance-service mapping engine) can write
 * `import type { VulnSeverity } from '@aicc/shared/types'` and read
 * semantically clear code at the call site.
 *
 * Part of the F-1 build-breaking bug fix (ComplianceOfficer turn-3).
 */
export type VulnSeverity = Severity;

/**
 * Shared `VulnKind` enum — the **finding-class** taxonomy.
 *
 * **Single source of truth**: this type is `z.infer`-derived from
 * `VulnerabilityKindSchema` in `backend/models/security/vulnerability.model.ts`.
 * Any change to the wire format (5 values: `'sca' | 'sast' | 'runtime' | 'container' | 'iac'`)
 * ripples through this type automatically. **No drift possible.**
 *
 * The trailing `'unknown'` is a **consumer-side runtime normalization
 * fallback**, not part of the wire format. When a wire payload omits
 * `kind` (legacy emitters) or specifies an invalid value, the consumer
 * normalizes to `'unknown'`. The compliance mapping engine
 * (`compliance-service`) accepts `VulnKind` with this fallback so it
 * never has to cast.
 *
 * **Distinct from** the SCAN_TOPIC `scanner` enum (trivy/grype/etc.),
 * which is the **scanner identification** and lives in
 * `backend/packages/shared/src/security/topics.ts:SecurityScanCompletedEvent`.
 *
 * **Distinct from** the broader 6-value union previously declared here
 * manually (which included `'dast'` and `'manual'`). Those values are
 * reserved for a future wire-format extension; the TS type now tracks
 * the wire format exactly.
 *
 * Part of the F-1 build-breaking bug fix (ComplianceOfficer turn-3)
 * plus the F-1 follow-up (turn-4): swap manual union for `z.infer`-derived
 * type. The wire Zod schema is the single source of truth.
 */
export const VulnKindSchema = VulnerabilityKindSchema;
export type VulnKind = z.infer<typeof VulnKindSchema> | 'unknown';

export interface VulnerabilityFinding extends BaseEntity, TenantScoped {
  scanId: UUID;
  cveId?: string;
  packageName?: string;
  packageVersion?: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  remediation?: string;
  status: 'open' | 'triaging' | 'in_progress' | 'resolved' | 'suppressed';
}

export type IncidentSeverity = Severity;
export type IncidentStatus = 'open' | 'acknowledged' | 'mitigating' | 'resolved' | 'closed';

export interface Incident extends BaseEntity, TenantScoped {
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assigneeId?: UUID;
  relatedFindingIds: UUID[];
  runbookId?: UUID;
}

export interface Runbook extends BaseEntity, TenantScoped {
  name: string;
  description: string;
  steps: Array<{ order: number; title: string; detail: string }>;
  triggers: string[];
}

export type ComplianceFramework = 'cis_v8' | 'nist_800_53' | 'soc2' | 'iso_27001';

export interface ComplianceControl extends BaseEntity, TenantScoped {
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  status: 'pass' | 'fail' | 'not_applicable' | 'manual_review';
  evidenceRefs: string[];
}

export type IntegrationProvider = 'github' | 'gitlab' | 'bitbucket' | 'jira' | 'slack';

export interface Integration extends BaseEntity, TenantScoped {
  provider: IntegrationProvider;
  name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  lastSyncAt?: string;
}
