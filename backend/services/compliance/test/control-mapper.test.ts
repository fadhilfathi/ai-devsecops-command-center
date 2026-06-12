// Unit tests for the control-mapper module.
//
// Run with: `tsx test/control-mapper.test.ts` from this directory.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { MappingEngine, type MappingInput } from '../src/control-mapper/index.js';
import mappingRules from '../src/control-mapper/mapping-rules.json' with { type: 'json' };

const fixedNow = () => Date.parse('2026-06-12T00:00:00Z');
const engine = new MappingEngine({ rules: mappingRules as any, now: fixedNow });

const T = 'tnt_test';

function input(over: Partial<MappingInput>): MappingInput {
  return {
    vulnId: 'v-1',
    tenantId: T,
    severity: 'medium',
    kind: 'unknown',
    kev: false,
    assetId: 'a-1',
    ...over,
  };
}

test('default rule (NIST SI-2) fires for all severities', () => {
  const r = engine.evaluate(input({ vulnId: 'v-1', severity: 'low' }));
  const ids = r.matches.map((m) => m.controlId);
  assert.ok(ids.includes('SI-2'));
  assert.ok(ids.includes('RA-5'));
});

test('CIS Control 7 fires only at medium+', () => {
  const lo = engine.evaluate(input({ vulnId: 'v-low', severity: 'low' }));
  const med = engine.evaluate(input({ vulnId: 'v-med', severity: 'medium' }));
  const hi = engine.evaluate(input({ vulnId: 'v-hi', severity: 'high' }));
  const crit = engine.evaluate(input({ vulnId: 'v-crit', severity: 'critical' }));
  assert.equal(lo.matches.find((m) => m.controlId === '7'), undefined);
  assert.ok(med.matches.find((m) => m.controlId === '7'));
  assert.ok(hi.matches.find((m) => m.controlId === '7'));
  assert.ok(crit.matches.find((m) => m.controlId === '7'));
});

test('CIS Control 16 fires only for SCA findings', () => {
  const sca = engine.evaluate(input({ vulnId: 'v-sca', kind: 'sca' }));
  const sast = engine.evaluate(input({ vulnId: 'v-sast', kind: 'sast' }));
  assert.ok(sca.matches.find((m) => m.controlId === '16'));
  assert.equal(sast.matches.find((m) => m.controlId === '16'), undefined);
});

test('NIST SI-7 fires only for KEV-flagged CVEs', () => {
  const kev = engine.evaluate(input({ vulnId: 'v-kev', kev: true, severity: 'critical' }));
  const nokev = engine.evaluate(input({ vulnId: 'v-nokev', kev: false, severity: 'critical' }));
  assert.ok(kev.matches.find((m) => m.controlId === 'SI-7'));
  assert.equal(nokev.matches.find((m) => m.controlId === 'SI-7'), undefined);
});

test('NIST SA-11 fires only for CVEs introduced within 30 days', () => {
  const recent = engine.evaluate(input({ vulnId: 'v-recent', introducedAt: '2026-06-01T00:00:00Z' }));
  const old = engine.evaluate(input({ vulnId: 'v-old', introducedAt: '2025-01-01T00:00:00Z' }));
  const future = engine.evaluate(input({ vulnId: 'v-future', introducedAt: '2026-12-01T00:00:00Z' }));
  const noIntro = engine.evaluate(input({ vulnId: 'v-no', introducedAt: undefined }));
  assert.ok(recent.matches.find((m) => m.controlId === 'SA-11'));
  assert.equal(old.matches.find((m) => m.controlId === 'SA-11'), undefined);
  assert.equal(future.matches.find((m) => m.controlId === 'SA-11'), undefined);
  assert.equal(noIntro.matches.find((m) => m.controlId === 'SA-11'), undefined);
});

test('batch evaluation deduplicates tuples and aggregates per-control', () => {
  const r = engine.evaluateBatch([
    input({ vulnId: 'a', severity: 'high', kind: 'sca' }),
    input({ vulnId: 'b', severity: 'low', kind: 'sca' }),
    input({ vulnId: 'c', severity: 'critical', kev: true, kind: 'sca' }),
  ]);
  // SI-2 and RA-5 should appear 3 times (all CVEs).
  const si2 = r.tuples.filter((t) => t.controlId === 'SI-2');
  assert.equal(si2.length, 3);
  // SI-7 only for KEV.
  const si7 = r.tuples.filter((t) => t.controlId === 'SI-7');
  assert.equal(si7.length, 1);
  assert.equal(si7[0].vulnId, 'c');
  // CIS 7 only at medium+.
  const cis7 = r.tuples.filter((t) => t.controlId === '7');
  assert.equal(cis7.length, 2); // 'a' and 'c'
  // Control summary has highest severity per control.
  const cis7sum = r.controlSummary.get('7');
  assert.equal(cis7sum?.highestSeverity, 'critical');
});
