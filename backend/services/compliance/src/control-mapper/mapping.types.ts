// Mapping engine types
//
// The mapping engine consumes a batch of vulnerability inputs and applies
// the rule set declared in mapping-rules.json, producing (controlId,
// vulnId) tuples that drive POA&M auto-creation and evidence attachment.

import type { Framework, ComplianceControlStatus } from '@aicc/shared/types/domain';

/** Severity scale (descending). Unknown is below Low. */
export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

/** Origin / detection kind. */
export type VulnKind = 'sca' | 'sast' | 'dast' | 'runtime' | 'manual' | 'unknown';

/**
 * Normalized vulnerability input. The engine accepts either a bare
 * VulnerabilityFinding (shared types) or a richer event-bus shape with
 * KEV / introducedAt / kind / source. The engine normalizes via
 * `toMappingInput()` before evaluating predicates.
 */
export interface MappingInput {
  /** Stable ID for the finding (e.g., ULID or UUID). */
  vulnId: string;
  /** Tenant the finding belongs to. */
  tenantId: string;
  /** CVE id, e.g. CVE-2024-3094. Optional for non-CVE findings. */
  cveId?: string;
  /** Severity at evaluation time. */
  severity: VulnSeverity;
  /** Detection source. */
  kind: VulnKind;
  /** True if listed in CISA KEV. */
  kev: boolean;
  /** ISO-8601 timestamp of when the vuln was introduced (e.g., commit date for SCA findings). */
  introducedAt?: string;
  /** Asset the finding is attached to. */
  assetId: string;
  /** Package / component identifier (for SBOM cross-ref). */
  componentId?: string;
  /** Free-form metadata preserved through evaluation. */
  metadata?: Record<string, unknown>;
}

/** Output of a single (rule, input) match. */
export interface ControlMapping {
  ruleId: string;
  controlId: string;
  framework: Framework;
  title: string;
  description: string;
  /** SLA in calendar days for remediating this vuln against this control. */
  slaDays: number;
  /** Priority (higher = more important). Used for tie-breaking when sorting. */
  priority: number;
  /** Derived control status contribution: 'fail' if the rule matches, else skipped. */
  contributes: 'fail';
}

/** A (controlId, vulnId) tuple ready for POA&M and evidence pipelines. */
export interface ControlVulnTuple {
  controlId: string;
  vulnId: string;
  framework: Framework;
  ruleId: string;
  severity: VulnSeverity;
  slaDays: number;
  dueAt: string;
}

// ---------------------------------------------------------------------------
// Predicate DSL
// ---------------------------------------------------------------------------

/** All predicate shapes are pure data, JSON-serializable. */
export type Predicate =
  | { type: 'always' }
  | { type: 'severity_gte'; value: VulnSeverity }
  | { type: 'severity_eq'; value: VulnSeverity }
  | { type: 'kind_eq'; value: VulnKind }
  | { type: 'kev'; value: boolean }
  | { type: 'introduced_within_days'; value: number }
  | { type: 'cve_pattern'; value: string }
  | { type: 'asset_pattern'; value: string }
  | { type: 'component_pattern'; value: string }
  | { type: 'and'; clauses: Predicate[] }
  | { type: 'or'; clauses: Predicate[] }
  | { type: 'not'; clause: Predicate };

/** A single rule from mapping-rules.json. */
export interface MappingRule {
  ruleId: string;
  framework: Framework;
  controlId: string;
  title: string;
  description: string;
  predicate: Predicate;
  slaDays: number;
  priority: number;
  enabled: boolean;
}

/** The full rules file. */
export interface MappingRulesFile {
  version: string;
  description: string;
  rules: MappingRule[];
}

/** A result of evaluating the rules against a single vuln. */
export interface MappingEvaluation {
  input: MappingInput;
  matches: ControlMapping[];
  /** Effective status: 'fail' if any rule matched, else 'pass'. */
  effectiveStatus: ComplianceControlStatus;
  evaluatedAt: string;
}

/** A batch result: every input evaluated, with all matches. */
export interface MappingBatchResult {
  tenantId: string;
  evaluatedAt: string;
  rulesVersion: string;
  /** One evaluation per input vuln. */
  evaluations: MappingEvaluation[];
  /** Flattened (controlId, vulnId) tuples, deduplicated. */
  tuples: ControlVulnTuple[];
  /** Per-control summary: which vulnIds matched the control. */
  controlSummary: Map<string, { controlId: string; framework: Framework; vulnIds: string[]; highestSeverity: VulnSeverity }>;
}
