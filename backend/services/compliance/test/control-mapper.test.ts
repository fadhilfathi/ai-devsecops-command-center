// Unit tests for the control-mapper (predicate DSL + rule engine).
// Run with: vitest run (pnpm --filter @aicc/compliance-service test)

import { test, expect } from 'vitest';
import { evaluatePredicate, MappingEngine, type MappingInput, type Predicate } from '../src/control-mapper/index.js';
import mappingRules from '../src/control-mapper/mapping-rules.json' with { type: 'json' };

const NOW = new Date('2026-06-12T00:00:00Z');

function makeInput(overrides: Partial<MappingInput> = {}): MappingInput {
  return {
    vulnId: 'v-1',
    tenantId: 't-1',
    cveId: 'CVE-2024-1234',
    severity: 'medium',
    kind: 'sca',
    kev: false,
    assetId: 'img-1',
    introducedAt: new Date(NOW.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Predicate primitives
// ---------------------------------------------------------------------------

test('severity_gte: critical >= high, medium is not', () => {
  const pred: Predicate = { type: 'severity_gte', value: 'high' };
  expect(evaluatePredicate(pred, makeInput({ severity: 'critical' }))).toBe(true);
  expect(evaluatePredicate(pred, makeInput({ severity: 'medium' }))).toBe(false);
});

test('kind_eq: matches exactly', () => {
  const pred: Predicate = { type: 'kind_eq', value: 'sca' };
  expect(evaluatePredicate(pred, makeInput({ kind: 'sca' }))).toBe(true);
  expect(evaluatePredicate(pred, makeInput({ kind: 'sast' }))).toBe(false);
});

test('kev: matches the requested boolean value', () => {
  const pred: Predicate = { type: 'kev', value: true };
  expect(evaluatePredicate(pred, makeInput({ kev: true }))).toBe(true);
  expect(evaluatePredicate(pred, makeInput({ kev: false }))).toBe(false);
});

test('introduced_within_days: true for recent, false for old', () => {
  const pred: Predicate = { type: 'introduced_within_days', value: 30 };
  const recent = makeInput({ introducedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() });
  const old = makeInput({ introducedAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString() });
  expect(evaluatePredicate(pred, recent)).toBe(true);
  expect(evaluatePredicate(pred, old)).toBe(false);
});

test('cve_pattern: regex on cveId', () => {
  const pred: Predicate = { type: 'cve_pattern', value: '^CVE-2024-' };
  expect(evaluatePredicate(pred, makeInput({ cveId: 'CVE-2024-1234' }))).toBe(true);
  expect(evaluatePredicate(pred, makeInput({ cveId: 'CVE-2023-9999' }))).toBe(false);
});

test('and: all children must match', () => {
  const pred: Predicate = {
    type: 'and',
    clauses: [{ type: 'severity_gte', value: 'high' }, { type: 'kev', value: true }],
  };
  expect(evaluatePredicate(pred, makeInput({ severity: 'high', kev: true }))).toBe(true);
  expect(evaluatePredicate(pred, makeInput({ severity: 'high', kev: false }))).toBe(false);
});

test('or: any child may match', () => {
  const pred: Predicate = {
    type: 'or',
    clauses: [{ type: 'severity_gte', value: 'critical' }, { type: 'kev', value: true }],
  };
  expect(evaluatePredicate(pred, makeInput({ severity: 'medium', kev: true }))).toBe(true);
  expect(evaluatePredicate(pred, makeInput({ severity: 'low', kev: false }))).toBe(false);
});

test('not: inverts a single child', () => {
  const pred: Predicate = { type: 'not', clause: { type: 'kev', value: true } };
  expect(evaluatePredicate(pred, makeInput({ kev: true }))).toBe(false);
  expect(evaluatePredicate(pred, makeInput({ kev: false }))).toBe(true);
});

// ---------------------------------------------------------------------------
// MappingEngine — integration against the shipped mapping-rules.json
// ---------------------------------------------------------------------------

test('critical KEV finding matches CIS-7, CIS-16, SI-2, RA-5, and SI-7', () => {
  const engine = new MappingEngine({ rules: mappingRules as never, now: () => NOW.getTime() });
  const evaluation = engine.evaluate(makeInput({ severity: 'critical', kev: true, kind: 'sca' }));
  const controlIds = evaluation.matches.map((m) => m.controlId).sort();
  expect(controlIds).toEqual(['16', '7', 'RA-5', 'SI-2', 'SI-7']);
  expect(evaluation.effectiveStatus).toBe('fail');
});

test('low-severity non-SCA finding still hits the always-on catch-all rules', () => {
  const engine = new MappingEngine({ rules: mappingRules as never, now: () => NOW.getTime() });
  const evaluation = engine.evaluate(makeInput({ severity: 'low', kind: 'sast', kev: false }));
  const controlIds = evaluation.matches.map((m) => m.controlId).sort();
  expect(controlIds).toEqual(['RA-5', 'SI-2']);
});

test('disabled rules are excluded from the engine', () => {
  const rules = { ...mappingRules, rules: mappingRules.rules.map((r) => ({ ...r, enabled: false })) };
  const engine = new MappingEngine({ rules: rules as never, now: () => NOW.getTime() });
  const evaluation = engine.evaluate(makeInput({ severity: 'critical', kev: true }));
  expect(evaluation.matches).toEqual([]);
  expect(evaluation.effectiveStatus).toBe('pass');
});
