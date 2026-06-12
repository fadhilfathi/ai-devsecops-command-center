// Mapping engine
//
// Consumes a batch of vulnerability inputs and applies the rule set
// declared in mapping-rules.json. Produces:
//   - per-input evaluations with their matches
//   - a flattened list of (controlId, vulnId) tuples for downstream POA&M
//   - a per-control summary (used to update control status)
//
// The engine is pure: no I/O, no event emission. Callers wire the
// engine to persistence, event bus, and POA&M creation.

import type { VulnerabilityFinding, ComplianceControlStatus } from '@aicc/shared/types/domain';
import type {
  ControlMapping,
  ControlVulnTuple,
  MappingBatchResult,
  MappingEvaluation,
  MappingInput,
  MappingRule,
  MappingRulesFile,
  VulnKind,
  VulnSeverity,
} from './mapping.types.js';
import { evaluatePredicate } from './predicates.js';

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/**
 * Normalize a bare VulnerabilityFinding (shared types) into a MappingInput.
 * Tolerates missing optional fields and applies sensible defaults.
 */
export function toMappingInput(finding: VulnerabilityFinding): MappingInput {
  const enriched = finding as VulnerabilityFinding & Partial<Omit<MappingInput, 'vulnId' | 'tenantId' | 'assetId' | 'severity' | 'kind' | 'kev'>>;

  return {
    vulnId: finding.id,
    tenantId: finding.tenantId,
    cveId: finding.cveId,
    severity: normalizeSeverity(finding.severity),
    kind: normalizeKind(enriched.kind),
    kev: Boolean(enriched.kev),
    introducedAt: enriched.introducedAt,
    assetId: finding.assetId ?? 'unknown',
    componentId: finding.componentId,
    metadata: finding.metadata,
  };
}

/** Defensively normalize severity values from upstream services. */
export function normalizeSeverity(value: unknown): VulnSeverity {
  if (typeof value !== 'string') return 'unknown';
  const v = value.toLowerCase();
  if (v === 'critical' || v === 'crit') return 'critical';
  if (v === 'high') return 'high';
  if (v === 'medium' || v === 'med' || v === 'moderate') return 'medium';
  if (v === 'low') return 'low';
  if (v === 'info' || v === 'informational' || v === 'negligible') return 'info';
  return 'unknown';
}

export function normalizeKind(value: unknown): VulnKind {
  if (typeof value !== 'string') return 'unknown';
  const v = value.toLowerCase();
  if (v === 'sca' || v === 'sbom' || v === 'dependency') return 'sca';
  if (v === 'sast' || v === 'static') return 'sast';
  if (v === 'dast' || v === 'dynamic') return 'dast';
  if (v === 'runtime' || v === 'raptor' || v === 'eBPF'.toLowerCase()) return 'runtime';
  if (v === 'manual' || v === 'human') return 'manual';
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

export interface EngineOptions {
  /** Override the "now" used for introduced_within_days (testing). */
  now?: () => number;
  /** Filter to only these rule ids; if undefined, all enabled rules run. */
  ruleIds?: string[];
  /** Reference to the rules file. */
  rules: MappingRulesFile;
}

export class MappingEngine {
  private readonly rules: MappingRule[];
  private readonly now: () => number;
  private readonly ruleFilter: Set<string> | null;

  constructor(options: EngineOptions) {
    this.rules = options.rules.rules.filter((r) => r.enabled);
    this.now = options.now ?? Date.now;
    this.ruleFilter = options.ruleIds ? new Set(options.ruleIds) : null;
  }

  /** Evaluate a single input against all enabled rules. */
  evaluate(input: MappingInput): MappingEvaluation {
    const matches: ControlMapping[] = [];
    for (const rule of this.rules) {
      if (this.ruleFilter && !this.ruleFilter.has(rule.ruleId)) continue;
      try {
        if (evaluatePredicate(rule.predicate, input)) {
          matches.push({
            ruleId: rule.ruleId,
            controlId: rule.controlId,
            framework: rule.framework,
            title: rule.title,
            description: rule.description,
            slaDays: rule.slaDays,
            priority: rule.priority,
            contributes: 'fail',
          });
        }
      } catch (err) {
        // Predicate evaluation errors must never crash the engine.
        // They are surfaced as no-match for the offending rule and
        // the error is attached to metadata for observability.
        input.metadata = {
          ...(input.metadata ?? {}),
          mappingError: { ruleId: rule.ruleId, message: (err as Error).message },
        };
      }
    }

    // Sort by priority desc (highest first) for stable ordering.
    matches.sort((a, b) => b.priority - a.priority);

    return {
      input,
      matches,
      effectiveStatus: matches.length > 0 ? 'fail' : 'pass',
      evaluatedAt: new Date(this.now()).toISOString(),
    };
  }

  /** Evaluate a batch of inputs. */
  evaluateBatch(inputs: MappingInput[]): MappingBatchResult {
    const tenantId = inputs[0]?.tenantId ?? 'unknown';
    const evaluations = inputs.map((i) => this.evaluate(i));

    // Build control summary.
    const controlSummaryMap = new Map<
      string,
      { controlId: string; framework: MappingInput['tenantId'] extends never ? never : import('./mapping.types.js').VulnSeverity extends never ? never : import('@aicc/shared/types/domain').Framework; vulnIds: string[]; highestSeverity: VulnSeverity }
    >();

    const tuples: ControlVulnTuple[] = [];
    const tupleDedupe = new Set<string>();
    const SEVERITY_RANK: Record<VulnSeverity, number> = {
      critical: 4, high: 3, medium: 2, low: 1, info: 0, unknown: -1,
    };

    for (const ev of evaluations) {
      for (const m of ev.matches) {
        const key = `${m.controlId}::${ev.input.vulnId}`;
        if (!tupleDedupe.has(key)) {
          tupleDedupe.add(key);
          const dueAt = new Date(this.now() + m.slaDays * 24 * 60 * 60 * 1000).toISOString();
          tuples.push({
            controlId: m.controlId,
            vulnId: ev.input.vulnId,
            framework: m.framework,
            ruleId: m.ruleId,
            severity: ev.input.severity,
            slaDays: m.slaDays,
            dueAt,
          });
        }

        const existing = controlSummaryMap.get(m.controlId);
        if (!existing) {
          controlSummaryMap.set(m.controlId, {
            controlId: m.controlId,
            framework: m.framework,
            vulnIds: [ev.input.vulnId],
            highestSeverity: ev.input.severity,
          });
        } else {
          existing.vulnIds.push(ev.input.vulnId);
          if (SEVERITY_RANK[ev.input.severity] > SEVERITY_RANK[existing.highestSeverity]) {
            existing.highestSeverity = ev.input.severity;
          }
        }
      }
    }

    return {
      tenantId,
      evaluatedAt: new Date(this.now()).toISOString(),
      rulesVersion: this.rules.length > 0 ? '1.0.0' : 'empty',
      evaluations,
      tuples,
      controlSummary: controlSummaryMap,
    };
  }

  /** Helper: turn a batch of VulnerabilityFindings into a batch result. */
  evaluateFindings(findings: VulnerabilityFinding[]): MappingBatchResult {
    return this.evaluateBatch(findings.map(toMappingInput));
  }
}
