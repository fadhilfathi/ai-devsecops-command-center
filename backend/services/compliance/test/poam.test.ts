// Unit tests for the POA&M service.
//
// Run with: `tsx test/poam.test.ts` from this directory.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { PoamService, buildPoamRepository, type PoamItem, type ControlVulnTuple } from '../src/poam/index.js';
import { InMemoryEventBus, type EventEnvelope } from '@aicc/shared/events';

class CaptureBus extends InMemoryEventBus {
  public published: EventEnvelope<unknown>[] = [];
  async publish<T>(event: Omit<EventEnvelope<T>, 'eventId' | 'occurredAt'>) {
    // @ts-ignore
    this.published.push({ ...event, eventId: 'fixed', occurredAt: '2026-06-12T00:00:00Z' });
  }
}

const fixedNow = () => new Date('2026-06-12T00:00:00Z');
const T = 'tnt_test';
const U = 'usr_admin';

function makeTuple(over: Partial<ControlVulnTuple> = {}): ControlVulnTuple {
  return {
    controlId: 'SI-2',
    vulnId: 'v-1',
    framework: 'nist_800_53',
    ruleId: 'rule-1',
    severity: 'high',
    slaDays: 30,
    dueAt: '2026-07-12T00:00:00Z',
    ...over,
  };
}

test('createFromTuple dedupes against existing open POA&M', async () => {
  const bus = new CaptureBus();
  const repo = buildPoamRepository();
  const svc = new PoamService({ repo, bus, now: fixedNow });
  const t1 = makeTuple();
  const a = await svc.createFromTuple(T, t1);
  const b = await svc.createFromTuple(T, t1);
  assert.equal(a.deduplicated, false);
  assert.equal(b.deduplicated, true);
  assert.equal(b.poam.poamId, a.poam.poamId);
  // Only one event emitted.
  const created = bus.published.filter((e) => e.type === 'compliance.poam.created');
  assert.equal(created.length, 1);
});

test('severity-derived SLA: critical=7d, high=30d, medium=90d, low=180d', async () => {
  const bus = new CaptureBus();
  const repo = buildPoamRepository();
  const svc = new PoamService({ repo, bus, now: fixedNow });
  for (const [sev, expectedDays] of [['critical', 7], ['high', 30], ['medium', 90], ['low', 180]] as const) {
    const t = makeTuple({ severity: sev, vulnId: `v-${sev}` });
    const r = await svc.createFromTuple(T, t);
    const expected = new Date(fixedNow().getTime() + expectedDays * 86400_000).toISOString();
    assert.equal(r.poam.dueAt, expected);
  }
});

test('close requires at least one evidence ref', async () => {
  const bus = new CaptureBus();
  const repo = buildPoamRepository();
  const svc = new PoamService({ repo, bus, now: fixedNow });
  const r = await svc.createFromTuple(T, makeTuple());
  await assert.rejects(() => svc.close(T, r.poam.poamId, U, 'note', []), /requires at least one evidence/);
  const closed = await svc.close(T, r.poam.poamId, U, 'note', ['ev-1']);
  assert.equal(closed.status, 'closed');
  assert.equal(closed.evidenceRefs.length, 1);
});

test('invalid transitions are rejected', async () => {
  const bus = new CaptureBus();
  const repo = buildPoamRepository();
  const svc = new PoamService({ repo, bus, now: fixedNow });
  const r = await svc.createFromTuple(T, makeTuple());
  await svc.close(T, r.poam.poamId, U, 'note', ['ev-1']);
  // closed -> in_progress is not allowed
  await assert.rejects(() => svc.startProgress(T, r.poam.poamId, U), /Invalid/);
});

test('scanForOverdue marks past-due open items and emits events', async () => {
  const bus = new CaptureBus();
  const repo = buildPoamRepository();
  const now = fixedNow;
  // Manually insert a past-due item.
  const past = makeTuple({ vulnId: 'v-past', controlId: 'SI-2' });
  const pastPoam: PoamItem = {
    poamId: 'p-past',
    tenantId: T,
    controlId: past.controlId,
    framework: past.framework,
    vulnId: past.vulnId,
    ruleId: past.ruleId,
    title: 'past',
    description: 'past',
    severity: 'high',
    status: 'open',
    source: 'auto',
    createdAt: '2026-05-01T00:00:00Z',
    createdBy: 'system',
    dueAt: '2026-05-15T00:00:00Z', // 28 days ago
    evidenceRefs: [],
    metadata: {},
  };
  await repo.create(pastPoam);
  // And one future.
  const futurePoam = { ...pastPoam, poamId: 'p-future', dueAt: '2026-12-31T00:00:00Z' };
  await repo.create(futurePoam);

  const svc = new PoamService({ repo, bus, now });
  const marked = await svc.scanForOverdue();
  assert.equal(marked.length, 1);
  assert.equal(marked[0].poamId, 'p-past');
  assert.equal(marked[0].status, 'overdue');
  const overdueEvents = bus.published.filter((e) => e.type === 'compliance.poam.overdue');
  assert.equal(overdueEvents.length, 1);
});

test('list filter for overdue', async () => {
  const bus = new CaptureBus();
  const repo = buildPoamRepository();
  const now = fixedNow;
  await repo.create({
    poamId: 'p-1', tenantId: T, controlId: 'SI-2', framework: 'nist_800_53',
    title: 't', description: 'd', severity: 'high', status: 'open', source: 'auto',
    createdAt: '2026-05-01T00:00:00Z', createdBy: 'sys', dueAt: '2026-05-15T00:00:00Z',
    evidenceRefs: [], metadata: {},
  });
  const svc = new PoamService({ repo, bus, now });
  const overdue = await svc.list(T, { status: 'overdue' });
  assert.equal(overdue.items.length, 1);
  assert.equal(overdue.items[0].poamId, 'p-1');
});
