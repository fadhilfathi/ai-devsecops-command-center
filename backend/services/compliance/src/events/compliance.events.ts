// Compliance service event payload types + topic re-exports.
//
// After the shared-types integration (mid-Sprint 2), the canonical topic
// strings live on `EventTypes` in @aicc/shared/events. This file:
//   1. Re-exports those topic constants under the historical local name
//      `ComplianceEventTypes` so existing call sites in poam.service.ts
//      and evidence-attacher.ts keep working.
//   2. Owns the typed payload interfaces (which the shared module does
//      not yet export). When the shared module adds payload types, this
//      file becomes a type-only re-export.
//
// Bus envelope contract: callers pass `Omit<EventEnvelope<T>, 'eventId' | 'occurredAt'>`
// — the bus injects those fields at publish time. Do not set them manually.

import type { Severity } from '@aicc/shared/events';
import { EventTypes } from '@aicc/shared/events';

// ---------------------------------------------------------------------------
// Topic re-exports (single source of truth lives in @aicc/shared/events)
// ---------------------------------------------------------------------------

export const ComplianceEventTypes = {
  CONTROL_UPDATED: EventTypes.COMPLIANCE_CONTROL_UPDATED,
  CONTROL_VIOLATED: EventTypes.COMPLIANCE_CONTROL_VIOLATED,
  EVIDENCE_ATTACHED: EventTypes.COMPLIANCE_EVIDENCE_ATTACHED,
  POAM_CREATED: EventTypes.COMPLIANCE_POAM_CREATED,
  POAM_CLOSED: EventTypes.COMPLIANCE_POAM_CLOSED,
  POAM_OVERDUE: EventTypes.COMPLIANCE_POAM_OVERDUE,
} as const;

export type ComplianceEventType = (typeof ComplianceEventTypes)[keyof typeof ComplianceEventTypes];

// ---------------------------------------------------------------------------
// Payload interfaces
// ---------------------------------------------------------------------------

/** Emitted whenever a ComplianceControl is created or its status changes. */
export interface ComplianceControlUpdatedEvent {
  tenantId: string;
  controlId: string;
  framework: 'cis_v8' | 'nist_800_53' | 'soc2' | 'iso_27001';
  status: 'pass' | 'fail' | 'not_applicable' | 'manual_review';
  kind: 'created' | 'status_changed' | 'evidence_attached';
  /** When kind === 'status_changed'. */
  previousStatus?: 'pass' | 'fail' | 'not_applicable' | 'manual_review';
  /** Triggering scanId (when applicable). */
  scanId?: string;
  /** Triggering vulnId (when applicable). */
  vulnId?: string;
  /** When evidence was attached. */
  evidenceId?: string;
}

/** Emitted per control when a scan finds one or more findings that map to it. */
export interface ComplianceControlViolatedEvent {
  tenantId: string;
  controlId: string;
  framework: 'cis_v8' | 'nist_800_53' | 'soc2' | 'iso_27001';
  maxSeverity: Severity;
  findingIds: string[];
  scanId: string;
  assetId: string;
}

/** Emitted each time a new evidence record is appended for a control. */
export interface ComplianceEvidenceAttachedEvent {
  tenantId: string;
  controlId: string;
  evidenceId: string;
  kind: 'screenshot' | 'log' | 'config' | 'attestation' | 'other';
  source: string; // 'sbom' | 'scan_report' | 'manual' | ...
  ref: string;    // object store path
  contentHash: string;
  size: number;
}

/** Emitted when a POA&M item is created (auto from a scan, or manual). */
export interface CompliancePoamCreatedEvent {
  tenantId: string;
  poamId: string;
  controlId: string;
  controlName: string;
  framework: 'cis_v8' | 'nist_800_53' | 'soc2' | 'iso_27001';
  severity: Severity;
  source: 'auto' | 'manual';
  dueAt: string;
  ruleId?: string;
  matchedAt?: string;
}

/** Emitted when a POA&M item reaches the 'closed' terminal state. */
export interface CompliancePoamClosedEvent {
  tenantId: string;
  poamId: string;
  controlId: string;
  closedAt: string;
  closedBy: string;
  closureReason?: string;
}

/** Emitted by the hourly overdue sweep when an item is past its SLA. */
export interface CompliancePoamOverdueEvent {
  tenantId: string;
  poamId: string;
  controlId: string;
  severity: Severity;
  dueAt: string;
  daysOverdue: number;
}
