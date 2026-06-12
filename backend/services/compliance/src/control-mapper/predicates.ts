// Predicate evaluators
//
// Pure functions that evaluate Predicate nodes against a MappingInput.
// No I/O, no side effects, safe to call from any context.

import type { MappingInput, Predicate, VulnSeverity } from './mapping.types.js';

const SEVERITY_ORDER: Record<VulnSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  unknown: -1,
};

const DAY_MS = 24 * 60 * 60 * 1000;

/** Severity at-or-above comparison. */
function severityGte(actual: VulnSeverity, threshold: VulnSeverity): boolean {
  return SEVERITY_ORDER[actual] >= SEVERITY_ORDER[threshold];
}

/** Regex compile with sane defaults; throws on bad pattern. */
function compileRegex(pattern: string): RegExp {
  return new RegExp(pattern, 'i');
}

/** True if `input.introducedAt` is within the last `days` calendar days. */
function introducedWithinDays(input: MappingInput, days: number): boolean {
  if (!input.introducedAt) return false;
  const introduced = Date.parse(input.introducedAt);
  if (Number.isNaN(introduced)) return false;
  const ageMs = Date.now() - introduced;
  return ageMs >= 0 && ageMs <= days * DAY_MS;
}

/** Evaluate one predicate node. */
export function evaluatePredicate(predicate: Predicate, input: MappingInput): boolean {
  switch (predicate.type) {
    case 'always':
      return true;

    case 'severity_gte':
      return severityGte(input.severity, predicate.value);

    case 'severity_eq':
      return input.severity === predicate.value;

    case 'kind_eq':
      return input.kind === predicate.value;

    case 'kev':
      return input.kev === predicate.value;

    case 'introduced_within_days':
      return introducedWithinDays(input, predicate.value);

    case 'cve_pattern':
      if (!input.cveId) return false;
      return compileRegex(predicate.value).test(input.cveId);

    case 'asset_pattern':
      return compileRegex(predicate.value).test(input.assetId);

    case 'component_pattern':
      if (!input.componentId) return false;
      return compileRegex(predicate.value).test(input.componentId);

    case 'and':
      return predicate.clauses.every((c) => evaluatePredicate(c, input));

    case 'or':
      return predicate.clauses.some((c) => evaluatePredicate(c, input));

    case 'not':
      return !evaluatePredicate(predicate.clause, input);

    default: {
      // Exhaustiveness check; compile error if a new predicate type is added
      // without an evaluator.
      const _exhaustive: never = predicate;
      void _exhaustive;
      return false;
    }
  }
}
