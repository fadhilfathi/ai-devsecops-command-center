// Unit tests for the POA&M service + repository (S2.9, post-integration rewrite).
// Run with: node --test backend/services/compliance/test/poam.test.ts
//
// Covers:
//   - Repository: dedup at (tenant, control, vuln), list filters, tenant isolation
//   - Service: createFromTuple idempotency, SLA ladder, valid-transition guard,
//     risk-acceptance short-circuit, overdue sweep
//   - Event bus: emits COMPLIANCE_POAM_CREATED on create, COMPLIANCE_POAM_CLOSED
//     on close, COMPLIANCE_POAM_OVERDUE on overdue sweep

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildPoamRepository, type PoamRepository } from '../src/poam/index.js';
import { PoamService } from '../src/poam/index.js';
import { POAM_SLA_DAYS } from '../src/poam/index.js';
import type { ControlVulnTuple } from '../src/control-mapper/index.js';
import { EventTypes } from '@aicc/shared/events';

// ---------------------------------------------------------------------------
// Test bus: a thin InMemoryEventBus capture for assertions
// ---------------------------------------------------------------------------

interface CapturedEvent { type: string; tenantId?: string; data?: unknown }

function makeBus() {
  const events: CapturedEvent[] = [];
  return {
    events,
    publish: async (e: { type: string; tenantId?: string; data?: unknown }) => {
      events.push({ type: e.type, tenantId: e.tenantId, data: e.data });
    },
    subscribe: async () => async () => {},
  };
}

function makeTuple(overrides: Partial<ControlVulnTuple> = {}): ControlVulnTuple {
  return {
    tenantId: 't-1',
    ruleId: 'r-cis7',
    controlId: 'CIS-7',
    framework: 'cis_v8',
    vulnId: 'v-1',
    severity: 'critical',
    kev: true,
    introducedAt: new Date('2026-06-05T00:00:00Z').toISOString(),
    matchedAt: new Date('2026-06-12T00:00:00Z').toISOString(),
    cveId: 'CVE-2024-1234',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

test('repo: createIfAbsent is idempotent at (tenant, control, vuln)', async () => {
  const repo: PoamRepository = buildPoamRepository();
  const t = makeTuple();
  const a = await repo.createIfAbsent({ ...t, id: 'p-1', createdAt: new Date().toISOString(), dueAt: new Date().toISOString() });
  const b = await repo.createIfAbsent({ ...t, id: 'p-2', createdAt: new Date().toISOString(), dueAt: new Date().toISOString() });
  assert.equal(a.id, b.id, 'second insert returns the same record');
});

test('repo: list with status=overdue returns only past-due non-closed items', async () => {
  const repo = buildPoamRepository();
  const now = new Date('2026-06-12T00:00:00Z');
  await repo.createIfAbsent({ ...makeTuple({ vulnId: 'low-1', severity: 'low' }), id: 'p-low', createdAt: now.toISOString(), dueAt: new Date(now.getTime() + 180 * 24 * 60 * 60 * 1000).toISOString() });
  await repo.createIfAbsent({ ...makeTuple({ vulnId: 'crit-1', severity: 'critical' }), id: 'p-crit', createdAt: now.toISOString(), dueAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString() });
  const future = new Date('2026-07-01T00:00:00Z');
  const overdue = await repo.list('t-1', { status: 'overdue', asOf: future });
  assert.equal(overdue.length, 1);
  assert.equal(overdue[0].vulnId, 'crit-1');
});

test('repo: tenant isolation — cannot read another tenant', async () => {
  const repo = buildPoamRepository();
  await repo.createIfAbsent({ ...makeTuple({ tenantId: 't-A' }), id: 'p-iso', createdAt: new Date().toISOString(), dueAt: new Date().toISOString() });
  const fetched = await repo.findById('t-B', 'p-iso');
  assert.equal(fetched, undefined);
});

// ---------------------------------------------------------------------------
// Service: create + dedup + SLA
// ---------------------------------------------------------------------------

test('service: createFromTuple is idempotent for the same tuple', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const t = makeTuple();
  const a = await svc.createFromTuple(t, 'system');
  const b = await svc.createFromTuple(t, 'system');
  assert.equal(a.id, b.id);
  // Only one COMPLIANCE_POAM_CREATED event was emitted
  const created = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CREATED);
  assert.equal(created.length, 1);
});

test('service: SLA ladder maps severity -> days', () => {
  assert.equal(POAM_SLA_DAYS.critical, 7);
  assert.equal(POAM_SLA_DAYS.high, 30);
  assert.equal(POAM_SLA_DAYS.medium, 90);
  assert.equal(POAM_SLA_DAYS.low, 180);
});

test('service: critical finding gets dueAt = now + 7d', async () => {
  const bus = makeBus();
  const now = new Date('2026-06-12T00:00:00Z');
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never, clock: () => now });
  const item = await svc.createFromTuple(makeTuple({ severity: 'critical' }), 'system');
  const expected = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
  assert.equal(item.dueAt, expected);
});

// ---------------------------------------------------------------------------
// Service: lifecycle + valid transitions
// ---------------------------------------------------------------------------

test('service: open -> in_progress -> pending_verification -> closed is valid', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const item = await svc.createFromTuple(makeTuple(), 'system');
  assert.equal(item.status, 'open');

  const ip = await svc.transition(item.id, { to: 'in_progress', actor: 'u-1' });
  assert.equal(ip.status, 'in_progress');

  const pv = await svc.transition(item.id, { to: 'pending_verification', actor: 'u-1' });
  assert.equal(pv.status, 'pending_verification');

  const closed = await svc.transition(item.id, { to: 'closed', actor: 'u-1', closureReason: 'patched' });
  assert.equal(closed.status, 'closed');
  assert.ok(closed.closedAt);

  // Events: 1 created + 1 closed (transitions don't emit on their own; they are state changes)
  const created = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CREATED);
  const closedEv = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CLOSED);
  assert.equal(created.length, 1);
  assert.equal(closedEv.length, 1);
});

test('service: invalid transition (open -> closed) is rejected', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const item = await svc.createFromTuple(makeTuple(), 'system');
  await assert.rejects(
    () => svc.transition(item.id, { to: 'closed', actor: 'u-1' }),
    /invalid transition/i
  );
  // No closed event was emitted
  const closedEv = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CLOSED);
  assert.equal(closedEv.length, 0);
});

test('service: risk acceptance short-circuits the lifecycle', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const item = await svc.createFromTuple(makeTuple(), 'system');
  const accepted = await svc.acceptRisk(item.id, {
    actor: 'u-1',
    justification: 'business-acceptable per CAB-2026-06-12',
    expiresAt: new Date('2027-06-12T00:00:00Z').toISOString(),
  });
  assert.equal(accepted.status, 'risk_accepted');
  assert.ok(accepted.riskAcceptance);
  assert.equal(accepted.riskAcceptance?.actor, 'u-1');

  // Cannot transition out of risk_accepted (terminal)
  await assert.rejects(
    () => svc.transition(item.id, { to: 'in_progress', actor: 'u-1' }),
    /invalid transition/i
  );
});

// ---------------------------------------------------------------------------
// Service: overdue sweep
// ---------------------------------------------------------------------------

test('service: scanForOverdue emits COMPLIANCE_POAM_OVERDUE once per item', async () => {
  const bus = makeBus();
  let now = new Date('2026-06-12T00:00:00Z');
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never, clock: () => now });
  await svc.createFromTuple(makeTuple({ severity: 'critical' }), 'system'); // due in 7d

  now = new Date('2026-06-25T00:00:00Z'); // 13 days later, past 7d SLA
  const first = await svc.scanForOverdue();
  assert.equal(first.length, 1);
  const overdue = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_OVERDUE);
  assert.equal(overdue.length, 1);

  // Second sweep with the same clock position should NOT re-emit
  bus.events.length = 0;
  const second = await svc.scanForOverdue();
  assert.equal(second.length, 1);
  assert.equal(bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_OVERDUE).length, 0);
});
