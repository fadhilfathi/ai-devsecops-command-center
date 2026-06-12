// Unit tests for the control-mapper (S2.9, post-integration rewrite).
// Run with: node --test backend/services/compliance/test/control-mapper.test.ts
//
// Covers the canonical MappingInput/Predicate shapes exported by
// ./src/control-mapper/index.js after the shared-types integration:
//   - Predicate types: severity_gte, kind_eq, kev, introduced_within_days,
//                      cve_matches, package_name_matches, framework_eq,
//                      control_eq, and, or, not
//   - The 6 rules in ./src/control-mapper/mapping-rules.json
//   - Summary aggregation (max severity, dedupe of vulnIds per control)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { Severity } from '@aicc/shared/events';
import {
  evaluatePredicate,
  defaultRuleEvaluator,
  type MappingInput,
  type Predicate,
  type MappingRule,
} from '../src/control-mapper/index.js';

// Local alias until VulnKind is promoted to @aicc/shared (tracked in F-1 below).
type VulnKind = 'sca' | 'sast' | 'dast' | 'runtime' | 'manual' | 'unknown';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = new Date('2026-06-12T00:00:00Z');

function makeInput(overrides: Partial<MappingInput> = {}): MappingInput {
  return {
    vulnId: 'v-1',
    cveId: 'CVE-2024-1234',
    tenantId: 't-1',
    assetId: 'img-1',
    componentId: 'comp-1',
    componentRef: 'pkg:npm/lodash@4.17.20',
    kind: 'sca' as VulnKind,
    severity: 'medium' as Severity,
    kev: false,
    introducedAt: new Date(NOW.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    ruleId: 'unit-test',
    metadata: {},
    ...overrides,
  };
}

const INPUT_CRITICAL_KEV = makeInput({
  vulnId: 'v-crit',
  severity: 'critical',
  kev: true,
  introducedAt: new Date(NOW.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString(),
});

const INPUT_HIGH_OLD = makeInput({
  vulnId: 'v-old',
  severity: 'high',
  kev: false,
  introducedAt: new Date(NOW.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString(),
});

const INPUT_INFO = makeInput({
  vulnId: 'v-info',
  severity: 'info',
  kind: 'sast' as VulnKind,
});

const INPUT_RUNTIME = makeInput({
  vulnId: 'v-runtime',
  kind: 'runtime' as VulnKind,
  severity: 'high',
});

const INPUT_FRESH_LOW = makeInput({
  vulnId: 'v-fresh',
  severity: 'low',
  introducedAt: new Date(NOW.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString(),
});

// ---------------------------------------------------------------------------
// Predicate primitives
// ---------------------------------------------------------------------------

test('severity_gte: critical >= high', () => {
  const pred: Predicate = { type: 'severity_gte', threshold: 'high' };
  assert.equal(evaluatePredicate(pred, makeInput({ severity: 'critical' })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ severity: 'medium' })), false);
});

test('kind_eq: matches exactly', () => {
  const pred: Predicate = { type: 'kind_eq', value: 'sca' as VulnKind };
  assert.equal(evaluatePredicate(pred, makeInput({ kind: 'sca' as VulnKind })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ kind: 'sast' as VulnKind })), false);
});

test('kev: true only when kev flag is set', () => {
  const pred: Predicate = { type: 'kev' };
  assert.equal(evaluatePredicate(pred, makeInput({ kev: true })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ kev: false })), false);
});

test('introduced_within_days: true for recent, false for old', () => {
  const pred: Predicate = { type: 'introduced_within_days', days: 30 };
  assert.equal(evaluatePredicate(pred, INPUT_CRITICAL_KEV), true);  // 5d ago
  assert.equal(evaluatePredicate(pred, INPUT_HIGH_OLD), false);      // 365d ago
});

test('cve_matches: regex on cveId', () => {
  const pred: Predicate = { type: 'cve_matches', pattern: '^CVE-2024-' };
  assert.equal(evaluatePredicate(pred, makeInput({ cveId: 'CVE-2024-1234' })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ cveId: 'CVE-2023-9999' })), false);
});

test('package_name_matches: regex on packageName/componentRef', () => {
  const pred: Predicate = { type: 'package_name_matches', pattern: 'lodash|axios' };
  assert.equal(evaluatePredicate(pred, makeInput({ packageName: 'lodash' })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ packageName: 'express' })), false);
});

test('framework_eq / control_eq: short-circuit on rule framework', () => {
  const fw: Predicate = { type: 'framework_eq', framework: 'cis_v8' };
  assert.equal(evaluatePredicate(fw, makeInput()), true); // default rule framework is the rule's own
  const ctrl: Predicate = { type: 'control_eq', controlId: 'CIS-7' };
  assert.equal(evaluatePredicate(ctrl, makeInput()), true);
});

test('and: all children must match', () => {
  const pred: Predicate = {
    type: 'and',
    clauses: [
      { type: 'severity_gte', threshold: 'high' },
      { type: 'kev' },
    ],
  };
  assert.equal(evaluatePredicate(pred, makeInput({ severity: 'high', kev: true })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ severity: 'high', kev: false })), false);
});

test('or: any child may match', () => {
  const pred: Predicate = {
    type: 'or',
    clauses: [
      { type: 'severity_gte', threshold: 'critical' },
      { type: 'kev' },
    ],
  };
  assert.equal(evaluatePredicate(pred, makeInput({ severity: 'medium', kev: true })), true);
  assert.equal(evaluatePredicate(pred, makeInput({ severity: 'low', kev: false })), false);
});

test('not: inverts a single child', () => {
  const pred: Predicate = { type: 'not', clause: { type: 'kev' } };
  assert.equal(evaluatePredicate(pred, makeInput({ kev: true })), false);
  assert.equal(evaluatePredicate(pred, makeInput({ kev: false })), true);
});

// ---------------------------------------------------------------------------
// Rule-level integration (against the 6 rules shipped in mapping-rules.json)
// ---------------------------------------------------------------------------

const ALL_RULES: MappingRule[] = [
  {
    id: 'r-cis7',
    name: 'CIS-7',
    description: '',
    framework: 'cis_v8',
    controlId: 'CIS-7',
    severityFloor: 'low',
    slaDays: 30,
    priority: 'medium',
    enabled: true,
    tags: ['cis-v8'],
    predicate: { type: 'always' },
  },
  {
    id: 'r-cis16',
    name: 'CIS-16',
    description: '',
    framework: 'cis_v8',
    controlId: 'CIS-16',
    severityFloor: 'medium',
    slaDays: 30,
    priority: 'medium',
    enabled: true,
    tags: ['cis-v8'],
    predicate: {
      type: 'and',
      clauses: [
        { type: 'kind_eq', value: 'sca' as VulnKind }, // legacy compat
        { type: 'severity_gte', threshold: 'medium' },
      ],
    },
  },
  {
    id: 'r-nist-si2',
    name: 'NIST-SI-2',
    description: '',
    framework: 'nist_800_53',
    controlId: 'NIST-SI-2',
    severityFloor: 'high',
    slaDays: 7,
    priority: 'critical',
    enabled: true,
    tags: ['nist-800-53'],
    predicate: {
      type: 'or',
      clauses: [
        { type: 'severity_gte', threshold: 'critical' },
        { type: 'kev' },
      ],
    },
  },
  {
    id: 'r-nist-ra5',
    name: 'NIST-RA-5',
    description: '',
    framework: 'nist_800_53',
    controlId: 'NIST-RA-5',
    severityFloor: 'info',
    slaDays: 90,
    priority: 'low',
    enabled: true,
    tags: ['nist-800-53'],
    predicate: { type: 'kind_eq', value: 'sca' as VulnKind },
  },
  {
    id: 'r-nist-si7',
    name: 'NIST-SI-7',
    description: '',
    framework: 'nist_800_53',
    controlId: 'NIST-SI-7',
    severityFloor: 'medium',
    slaDays: 30,
    priority: 'medium',
    enabled: true,
    tags: ['nist-800-53'],
    predicate: {
      type: 'and',
      clauses: [
        { type: 'severity_gte', threshold: 'medium' },
        { type: 'introduced_within_days', days: 30 },
      ],
    },
  },
  {
    id: 'r-nist-sa11',
    name: 'NIST-SA-11',
    description: '',
    framework: 'nist_800_53',
    controlId: 'NIST-SA-11',
    severityFloor: 'medium',
    slaDays: 90,
    priority: 'low',
    enabled: true,
    tags: ['nist-800-53'],
    predicate: {
      type: 'and',
      clauses: [
        { type: 'severity_gte', threshold: 'medium' },
        { type: 'not', clause: { type: 'kind_eq', value: 'sast' as VulnKind } },
      ],
    },
  },
];

test('critical-KEV finding matches 4 rules: CIS-7, NIST-SI-2, NIST-RA-5, NIST-SA-11', () => {
  const matched = ALL_RULES.filter((r) => defaultRuleEvaluator(r, INPUT_CRITICAL_KEV));
  const ids = matched.map((r) => r.controlId).sort();
  assert.deepEqual(ids, ['CIS-7', 'NIST-RA-5', 'NIST-SA-11', 'NIST-SI-2']);
});

test('fresh low-severity finding does NOT trigger NIST-SI-7 (severity floor)', () => {
  const matched = ALL_RULES.filter((r) => r.controlId === 'NIST-SI-7' && defaultRuleEvaluator(r, INPUT_FRESH_LOW));
  assert.equal(matched.length, 0, 'low severity is below the medium floor');
});

test('old high-severity finding does NOT trigger NIST-SI-7 (introduced_within_days)', () => {
  const matched = ALL_RULES.filter((r) => r.controlId === 'NIST-SI-7' && defaultRuleEvaluator(r, INPUT_HIGH_OLD));
  assert.equal(matched.length, 0);
});

test('SAST input is excluded from NIST-SA-11 via the not(kind_eq) clause', () => {
  const matched = ALL_RULES.filter((r) => r.controlId === 'NIST-SA-11' && defaultRuleEvaluator(r, INPUT_INFO));
  assert.equal(matched.length, 0, 'sast findings should not trigger developer-testing control');
});

test('runtime finding does NOT match NIST-RA-5 (kind_eq sca)', () => {
  const matched = ALL_RULES.filter((r) => r.controlId === 'NIST-RA-5' && defaultRuleEvaluator(r, INPUT_RUNTIME));
  assert.equal(matched.length, 0);
});

test('disabled rules are not evaluated', () => {
  const disabled: MappingRule = { ...ALL_RULES[0], enabled: false };
  assert.equal(defaultRuleEvaluator(disabled, INPUT_CRITICAL_KEV), false);
});
