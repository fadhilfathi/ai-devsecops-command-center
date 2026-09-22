// Unit tests for the infrastructure (runtime-security / k8s-health)
// finding listener — S6-4.
// Run with: vitest run (pnpm --filter @aicc/compliance-service test)

import { test, expect } from 'vitest';
import type { EventEnvelope } from '@aicc/shared/events';
import { EventTypes } from '@aicc/shared/events';
import { buildInfrastructureListener } from '../src/evidence/infrastructure-listener.js';
import { EvidenceAttacher } from '../src/evidence/evidence-attacher.js';
import { InMemoryBlobStore } from '../src/evidence/blob-store.memory.js';
import { buildEvidenceRepository } from '../src/repositories/evidence.repository.js';
import { buildPoamRepository, PoamService } from '../src/poam/index.js';
import { MappingEngine } from '../src/control-mapper/index.js';
import mappingRules from '../src/control-mapper/mapping-rules.json' with { type: 'json' };

function makeBus() {
  const events: Array<{ type: string; tenantId?: string; data?: unknown }> = [];
  return {
    events,
    publish: async (e: { type: string; tenantId?: string; data?: unknown }) => {
      events.push({ type: e.type, tenantId: e.tenantId, data: e.data });
    },
    subscribe: async () => {},
    close: async () => {},
  };
}

function buildAttacher() {
  const bus = makeBus();
  const evidenceRepo = buildEvidenceRepository();
  const poamRepo = buildPoamRepository();
  const poamService = new PoamService({ repo: poamRepo, bus: bus as never });
  const mappingEngine = new MappingEngine({ rules: mappingRules as never });
  const attacher = new EvidenceAttacher({
    store: new InMemoryBlobStore(),
    evidenceRepo,
    mappingEngine,
    poamService,
    bus: bus as never,
  });
  return { attacher, evidenceRepo, poamRepo, bus };
}

function runtimeRiskEnvelope(): EventEnvelope<unknown> {
  return {
    eventId: 'e-1',
    type: EventTypes.RUNTIME_RISK_DETECTED,
    version: 1,
    source: 'runtime-security-service',
    occurredAt: new Date().toISOString(),
    tenantId: 'tenant-1',
    data: {
      findings: [
        {
          id: 'risk-1',
          ruleId: 'AICC-RT-001',
          severity: 'critical',
          subjectKind: 'Pod',
          subjectName: 'payments-api-abc',
          clusterId: 'cluster-1',
          namespace: 'default',
        },
      ],
    },
  };
}

function healthIssueEnvelope(): EventEnvelope<unknown> {
  return {
    eventId: 'e-2',
    type: EventTypes.CLUSTER_HEALTH_ISSUE_DETECTED,
    version: 1,
    source: 'k8s-health-service',
    occurredAt: new Date().toISOString(),
    tenantId: 'tenant-1',
    data: {
      findings: [
        {
          id: 'issue-1',
          kind: 'crash_loop_back_off',
          severity: 'critical',
          subject: {
            kind: 'Pod',
            name: 'payments-api-abc',
            namespace: 'default',
            clusterId: 'cluster-1',
          },
        },
      ],
    },
  };
}

test('a runtime risk event creates a control failure (POA&M) and attaches evidence', async () => {
  const { attacher, evidenceRepo, poamRepo } = buildAttacher();
  const listeners = buildInfrastructureListener(attacher);
  const runtimeListener = listeners.find((l) => l.topic === EventTypes.RUNTIME_RISK_DETECTED)!;

  await runtimeListener.handler(runtimeRiskEnvelope());

  const evidence = await evidenceRepo.list('tenant-1');
  expect(evidence.length).toBeGreaterThan(0);
  expect(evidence.map((e) => e.controlId).sort()).toEqual(['4', 'AC-6', 'CM-6']);

  const poams = await poamRepo.list({ tenantId: 'tenant-1' });
  expect(poams.items.length).toBe(3);
  expect(poams.items.every((p) => p.vulnId === 'risk-1')).toBe(true);
});

test('a health issue event creates a control failure and attaches evidence', async () => {
  const { attacher, evidenceRepo, poamRepo } = buildAttacher();
  const listeners = buildInfrastructureListener(attacher);
  const healthListener = listeners.find(
    (l) => l.topic === EventTypes.CLUSTER_HEALTH_ISSUE_DETECTED,
  )!;

  await healthListener.handler(healthIssueEnvelope());

  const evidence = await evidenceRepo.list('tenant-1');
  expect(evidence.map((e) => e.controlId).sort()).toEqual(['CP-10', 'SI-4']);

  const poams = await poamRepo.list({ tenantId: 'tenant-1' });
  expect(poams.items.length).toBe(2);
  expect(poams.items.every((p) => p.vulnId === 'issue-1')).toBe(true);
});

test('re-processing the same finding (duplicate delivery) does not duplicate POA&M items', async () => {
  const { attacher, poamRepo } = buildAttacher();
  const listeners = buildInfrastructureListener(attacher);
  const runtimeListener = listeners.find((l) => l.topic === EventTypes.RUNTIME_RISK_DETECTED)!;

  await runtimeListener.handler(runtimeRiskEnvelope());
  await runtimeListener.handler(runtimeRiskEnvelope());

  const poams = await poamRepo.list({ tenantId: 'tenant-1' });
  // Deduplicated by (tenantId, controlId, vulnId) — same as the vuln flow.
  expect(poams.items.length).toBe(3);
});

test('re-processing the same finding (duplicate delivery) does not duplicate evidence rows', async () => {
  const { attacher, evidenceRepo } = buildAttacher();
  const listeners = buildInfrastructureListener(attacher);
  const runtimeListener = listeners.find((l) => l.topic === EventTypes.RUNTIME_RISK_DETECTED)!;

  await runtimeListener.handler(runtimeRiskEnvelope());
  const firstCount = (await evidenceRepo.list('tenant-1')).length;
  expect(firstCount).toBeGreaterThan(0);

  // k8s-health republishes every open issue on every poll — simulate that
  // by re-delivering the exact same finding (same id, so the same
  // content-addressed blob ref).
  await runtimeListener.handler(runtimeRiskEnvelope());
  await runtimeListener.handler(runtimeRiskEnvelope());

  const evidence = await evidenceRepo.list('tenant-1');
  // Deduplicated by (tenantId, controlId, ref) — must NOT grow on repeat
  // delivery of the same finding.
  expect(evidence.length).toBe(firstCount);
});

test('an unrelated event type is ignored', async () => {
  const { attacher, evidenceRepo } = buildAttacher();
  const listeners = buildInfrastructureListener(attacher);
  const runtimeListener = listeners.find((l) => l.topic === EventTypes.RUNTIME_RISK_DETECTED)!;

  await runtimeListener.handler({
    ...runtimeRiskEnvelope(),
    type: 'scan.completed',
  });

  const evidence = await evidenceRepo.list('tenant-1');
  expect(evidence).toEqual([]);
});
