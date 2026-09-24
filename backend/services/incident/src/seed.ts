/**
 * S8-1 — optional demo seed data (`AICC_DEMO_SEED=true`). Idempotent: skips
 * if the demo tenant already has incidents.
 */
import type { IncidentRepository } from './repositories/incident.repository.js';
import type { RunbookRepository } from './repositories/runbook.repository.js';

export async function seedDemoData(
  repos: { incidents: IncidentRepository; runbooks: RunbookRepository },
  tenantId: string,
): Promise<void> {
  const existing = await repos.incidents.list(tenantId);
  if (existing.length > 0) return;

  const runbook = await repos.runbooks.create({
    tenantId,
    name: 'Critical vulnerability response',
    description: 'Demo runbook seeded for local/demo environments.',
    steps: [
      { order: 1, title: 'Triage', detail: 'Confirm severity and blast radius.' },
      { order: 2, title: 'Contain', detail: 'Patch or isolate the affected asset.' },
      { order: 3, title: 'Verify', detail: 'Re-scan and confirm remediation.' },
    ],
    triggers: ['severity:critical'],
  });

  const critical = await repos.incidents.create({
    tenantId,
    title: 'Prototype pollution in lodash exploited in prod',
    description: 'Demo incident seeded for local/demo environments.',
    severity: 'critical',
    runbookId: runbook.id,
  });
  await repos.incidents.update(critical.id, tenantId, { status: 'mitigating' });

  await repos.incidents.create({
    tenantId,
    title: 'ReDoS in express under investigation',
    description: 'Demo incident seeded for local/demo environments.',
    severity: 'medium',
  });

  const resolved = await repos.incidents.create({
    tenantId,
    title: 'Exposed S3 bucket remediated',
    description: 'Demo incident seeded for local/demo environments.',
    severity: 'high',
  });
  await repos.incidents.update(resolved.id, tenantId, { status: 'resolved' });
}
