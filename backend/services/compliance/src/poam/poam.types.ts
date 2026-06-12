// POA&M (Plan of Action & Milestones) types
//
// A POA&M item is the unit of compliance remediation work. The
// compliance service auto-creates POA&M items from non-compliant
// control evaluations and supports manual creation via POST /poam.
//
// Lifecycle:
//   open -> in_progress -> awaiting_evidence -> closed
//                                                  |
//                            risk_accepted (parallel branch; expires)
//   open|in_progress|awaiting_evidence -> overdue (auto-set by scheduler)
//
// Status persistence rules:
//   - `closed` requires at least one attached evidence record.
//   - `risk_accepted` requires an `acceptedBy` user id, justification,
//     and an expiry date. The ComplianceOfficer role only.

import type { Framework } from '@aicc/shared/types/domain';

export type PoamSeverity = 'critical' | 'high' | 'medium' | 'low';

export type PoamStatus =
  | 'open'
  | 'in_progress'
  | 'awaiting_evidence'
  | 'closed'
  | 'risk_accepted'
  | 'overdue';

export type PoamSource = 'auto' | 'manual';

/** SLA in calendar days, derived from severity. */
export const POAM_SLA_DAYS: Record<PoamSeverity, number> = {
  critical: 7,
  high: 30,
  medium: 90,
  low: 180,
};

/** ISO-8601 string. */
export type Iso = string;

export interface PoamRiskAcceptance {
  acceptedBy: string;
  acceptedAt: Iso;
  justification: string;
  expiresAt: Iso;
  /** Optional compensating-control reference. */
  compensatingControlId?: string;
}

export interface PoamItem {
  poamId: string;
  tenantId: string;
  controlId: string;
  framework: Framework;
  /** The vuln id that triggered auto-creation, if any. */
  vulnId?: string;
  /** The rule id that triggered auto-creation, if any. */
  ruleId?: string;
  title: string;
  description: string;
  severity: PoamSeverity;
  status: PoamStatus;
  source: PoamSource;
  createdAt: Iso;
  createdBy: string;
  dueAt: Iso;
  closedAt?: Iso;
  closedBy?: string;
  resolutionNotes?: string;
  evidenceRefs: string[];
  riskAcceptance?: PoamRiskAcceptance;
  metadata: Record<string, unknown>;
}

/** Input for the POST /poam manual creation endpoint. */
export interface CreatePoamInput {
  controlId: string;
  framework: Framework;
  title: string;
  description: string;
  severity: PoamSeverity;
  /** Optional override of the SLA; if absent, derived from severity. */
  slaDays?: number;
  /** Optional associated vuln (for cross-ref). */
  vulnId?: string;
  /** Optional metadata. */
  metadata?: Record<string, unknown>;
}

/** Returned from the service after creation. */
export interface CreatePoamResult {
  poam: PoamItem;
  /** True if the service deduplicated against an existing open POA&M. */
  deduplicated: boolean;
}

/** Filter for GET /poam. */
export interface ListPoamFilter {
  status?: PoamStatus | 'all';
  controlId?: string;
  framework?: Framework;
  vulnId?: string;
  /** Only items with dueAt <= now. */
  dueBefore?: Iso;
  /** Only items with dueAt >= now. */
  dueAfter?: Iso;
  /** Cursor-based pagination. */
  cursor?: string;
  limit?: number;
}
