// Unit tests for the POA&M service + repository.
// Run with: vitest run (pnpm --filter @aicc/compliance-service test)

import { test, expect } from 'vitest';
import {
  buildPoamRepository,
  PoamService,
  POAM_SLA_DAYS,
  type PoamRepository,
} from '../src/poam/index.js';
import type { ControlVulnTuple } from '../src/control-mapper/index.js';
import { EventTypes } from '@aicc/shared/events';

interface CapturedEvent {
  type: string;
  tenantId?: string;
  data?: unknown;
}

function makeBus() {
  const events: CapturedEvent[] = [];
  return {
    events,
    publish: async (e: { type: string; tenantId?: string; data?: unknown }) => {
      events.push({ type: e.type, tenantId: e.tenantId, data: e.data });
    },
    subscribe: async () => {},
    close: async () => {},
  };
}

function makeTuple(overrides: Partial<ControlVulnTuple> = {}): ControlVulnTuple {
  return {
    controlId: '7',
    vulnId: 'v-1',
    framework: 'cis_v8',
    ruleId: 'cis-7-continuous-vuln-management',
    severity: 'critical',
    slaDays: 30,
    dueAt: new Date('2026-06-19T00:00:00Z').toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

test('repo: create + getById round-trips, scoped by tenant', async () => {
  const repo: PoamRepository = buildPoamRepository();
  const created = await repo.create({
    poamId: 'p-1',
    tenantId: 't-1',
    controlId: '7',
    framework: 'cis_v8',
    title: 'x',
    description: 'x',
    severity: 'critical',
    status: 'open',
    source: 'manual',
    createdAt: new Date().toISOString(),
    createdBy: 'u-1',
    dueAt: new Date().toISOString(),
    evidenceRefs: [],
    metadata: {},
  });
  expect(await repo.getById('t-1', created.poamId)).toMatchObject({ poamId: 'p-1' });
  expect(await repo.getById('t-2', created.poamId)).toBe(null);
});

test('repo: findOpenForControlVuln ignores closed/risk_accepted items', async () => {
  const repo = buildPoamRepository();
  await repo.create({
    poamId: 'p-1',
    tenantId: 't-1',
    controlId: '7',
    framework: 'cis_v8',
    vulnId: 'v-1',
    title: 'x',
    description: 'x',
    severity: 'critical',
    status: 'closed',
    source: 'manual',
    createdAt: new Date().toISOString(),
    createdBy: 'u-1',
    dueAt: new Date().toISOString(),
    evidenceRefs: [],
    metadata: {},
  });
  expect(await repo.findOpenForControlVuln('t-1', '7', 'v-1')).toBe(null);
});

// ---------------------------------------------------------------------------
// Service: create from tuple + dedup + SLA
// ---------------------------------------------------------------------------

test('service: createFromTuple is idempotent for the same (controlId, vulnId)', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const t = makeTuple();
  const a = await svc.createFromTuple('t-1', t);
  const b = await svc.createFromTuple('t-1', t);
  expect(a.deduplicated).toBe(false);
  expect(b.deduplicated).toBe(true);
  expect(a.poam.poamId).toBe(b.poam.poamId);
  expect(bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CREATED).length).toBe(1);
});

test('service: SLA ladder maps severity -> days', () => {
  expect(POAM_SLA_DAYS.critical).toBe(7);
  expect(POAM_SLA_DAYS.high).toBe(30);
  expect(POAM_SLA_DAYS.medium).toBe(90);
  expect(POAM_SLA_DAYS.low).toBe(180);
});

test('service: critical tuple without an explicit slaDays override still uses tuple.slaDays', async () => {
  const bus = makeBus();
  const now = new Date('2026-06-12T00:00:00Z');
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never, now: () => now });
  const { poam } = await svc.createFromTuple('t-1', makeTuple({ slaDays: 7 }));
  const expected = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
  expect(poam.dueAt).toBe(expected);
});

// ---------------------------------------------------------------------------
// Service: lifecycle + valid transitions
// ---------------------------------------------------------------------------

test('service: open -> in_progress -> awaiting_evidence -> closed is valid', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const { poam } = await svc.createFromTuple('t-1', makeTuple());
  expect(poam.status).toBe('open');

  const ip = await svc.startProgress('t-1', poam.poamId, 'u-1');
  expect(ip.status).toBe('in_progress');

  const pv = await svc.markAwaitingEvidence('t-1', poam.poamId, 'u-1');
  expect(pv.status).toBe('awaiting_evidence');

  const closed = await svc.close('t-1', poam.poamId, 'u-1', 'patched', ['evidence-1']);
  expect(closed.status).toBe('closed');
  expect(closed.closedAt).toBeTruthy();

  const created = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CREATED);
  const closedEv = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_CLOSED);
  expect(created.length).toBe(1);
  expect(closedEv.length).toBe(1);
});

test('service: close() requires at least one evidence reference', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const { poam } = await svc.createFromTuple('t-1', makeTuple());
  await expect(svc.close('t-1', poam.poamId, 'u-1', 'notes', [])).rejects.toThrow(/evidence/i);
});

test('service: risk acceptance short-circuits the lifecycle', async () => {
  const bus = makeBus();
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never });
  const { poam } = await svc.createFromTuple('t-1', makeTuple());
  const accepted = await svc.acceptRisk(
    't-1',
    poam.poamId,
    'u-1',
    'business-acceptable per CAB-2026-06-12',
    new Date('2027-06-12T00:00:00Z').toISOString(),
  );
  expect(accepted.status).toBe('risk_accepted');
  expect(accepted.riskAcceptance?.acceptedBy).toBe('u-1');
});

// ---------------------------------------------------------------------------
// Service: overdue sweep
// ---------------------------------------------------------------------------

test('service: scanForOverdue marks past-due items and emits once', async () => {
  const bus = makeBus();
  let now = new Date('2026-06-12T00:00:00Z');
  const svc = new PoamService({ repo: buildPoamRepository(), bus: bus as never, now: () => now });
  await svc.createFromTuple('t-1', makeTuple({ slaDays: 7 })); // due in 7d

  now = new Date('2026-06-25T00:00:00Z'); // 13 days later, past the 7d SLA
  const first = await svc.scanForOverdue();
  expect(first.length).toBe(1);
  expect(first[0]!.status).toBe('overdue');
  const overdueEvents = bus.events.filter((e) => e.type === EventTypes.COMPLIANCE_POAM_OVERDUE);
  expect(overdueEvents.length).toBe(1);

  // A second sweep with the same clock position should not re-flag the item.
  const second = await svc.scanForOverdue();
  expect(second.length).toBe(0);
});
