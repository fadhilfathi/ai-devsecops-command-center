// Compliance service event payloads
//
// Centralized event-shape definitions for the events the compliance
// service emits. Consumers (SIEM, agent bus, customer notifications)
// rely on these shapes; changes must be versioned via the envelope's
// `version` field.
//
// Conventions:
//   - All times are ISO-8601 UTC strings.
//   - All ids are strings (uuid/ulid), no numeric types.
//   - All payloads include `tenantId` even when redundant with the
//     envelope, so consumers that filter on data alone (e.g., stream
//     analytics) work without unpacking the envelope.

import type { Framework, ComplianceControlStatus } from '@aicc/shared/types/domain';
import type { PoamSeverity, PoamSource } from '../poam/poam.types.js';
import type { VulnSeverity } from '../control-mapper/mapping.types.js';

// ---------------------------------------------------------------------------
// Event type constants
// ---------------------------------------------------------------------------

export const ComplianceEventTypes = {
  ControlViolated: 'compliance.control.violated',
  EvidenceAttached: 'compliance.evidence.attached',
  PoamCreated: 'compliance.poam.created',
  PoamClosed: 'compliance.poam.closed',
  PoamOverdue: 'compliance.poam.overdue',
} as const;

export type ComplianceEventType =
  (typeof ComplianceEventTypes)[keyof typeof ComplianceEventTypes];

// ---------------------------------------------------------------------------
// Event data shapes
// ---------------------------------------------------------------------------

/** Emitted when a control evaluation transitions to 'fail'. */
export interface ComplianceControlViolatedData {
  tenantId: string;
  controlId: string;
  framework: Framework;
  status: ComplianceControlStatus;
  violatingVulnIds: string[];
  firstObservedAt: string;
  /** Most-severe severity among the violating vulns. */
  highestSeverity: VulnSeverity;
  /** Rule id(s) that triggered the failure. */
  ruleIds: string[];
}

/** Emitted when an evidence record is attached to a control. */
export interface ComplianceEvidenceAttachedData {
  tenantId: string;
  evidenceId: string;
  controlIds: string[];
  assetId: string;
  evidenceType: 'sbom' | 'scan_report' | 'config' | 'attestation' | 'log';
  objectStorePath: string;
  hash: string;
  scanId?: string;
  tool?: string;
  collectedBy: string;
  collectedAt: string;
}

export interface CompliancePoamCreatedData {
  tenantId: string;
  poamId: string;
  controlId: string;
  framework: Framework;
  vulnId?: string;
  severity: PoamSeverity;
  dueAt: string;
  source: PoamSource;
  ruleId?: string;
}

export interface CompliancePoamClosedData {
  tenantId: string;
  poamId: string;
  controlId: string;
  framework: Framework;
  closedBy: string;
  resolutionNotes?: string;
  evidenceRefs: string[];
}

export interface CompliancePoamOverdueData {
  tenantId: string;
  poamId: string;
  controlId: string;
  framework: Framework;
  severity: PoamSeverity;
  dueAt: string;
  daysOverdue: number;
}
