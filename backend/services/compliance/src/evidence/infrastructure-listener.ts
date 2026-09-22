// Infrastructure finding listener
//
// Subscribes to `runtime.risk.detected` (runtime-security-service) and
// `cluster.health.issue.detected` (k8s-health-service). Each event carries
// a batch of findings (`findings[]` — the producers publish one event per
// request, not per finding, to avoid blocking the response — see the
// routes that compute them). The listener normalizes each finding into a
// `MappingInput` (subjectKind discriminates the rule set) and reuses the
// EvidenceAttacher's control-mapping / POA&M / evidence pipeline, exactly
// like the vulnerability scan flow in scan-listener.ts.
//
// Unlike the vulnerability scan flow, k8s-health republishes every open
// issue on every `GET /v1/health/issues` poll (there is no dedicated
// "scan" action), so this listener sees the same finding redelivered
// far more often than scan-listener does. Idempotency: POA&M creation
// is deduplicated by (tenantId, controlId, vulnId) in PoamService;
// evidence rows are deduplicated by (tenantId, controlId, blob ref) in
// EvidenceAttacher.attachInfrastructureFinding — the ref is deterministic
// per finding id, so a repeat delivery resolves to the same ref and is
// skipped rather than inserted again.

import type { EventEnvelope, EventHandler } from '@aicc/shared/events';
import { EventTypes } from '@aicc/shared/events';
import type { EvidenceAttacher } from './evidence-attacher.js';
import type { MappingInput } from '../control-mapper/index.js';

interface RuntimeRiskFinding {
  id: string;
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  subjectKind: string;
  subjectName: string;
  clusterId?: string;
  namespace?: string;
}

interface RuntimeRiskDetectedPayload {
  findings: RuntimeRiskFinding[];
}

interface ClusterHealthIssueFinding {
  id: string;
  kind: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  subject: { kind: string; name: string; namespace?: string; clusterId?: string };
}

interface ClusterHealthIssueDetectedPayload {
  findings: ClusterHealthIssueFinding[];
}

function fromRuntimeRisk(tenantId: string, f: RuntimeRiskFinding): MappingInput {
  return {
    vulnId: f.id,
    tenantId,
    severity: f.severity,
    kind: 'runtime',
    kev: false,
    assetId: f.subjectName,
    subjectKind: 'runtime_risk',
    ruleId: f.ruleId,
    resourceKind: f.subjectKind,
    namespace: f.namespace,
    clusterId: f.clusterId,
    workloadName: f.subjectName,
  };
}

function fromHealthIssue(tenantId: string, f: ClusterHealthIssueFinding): MappingInput {
  return {
    vulnId: f.id,
    tenantId,
    severity: f.severity,
    kind: 'runtime',
    kev: false,
    assetId: f.subject.name,
    subjectKind: 'health_issue',
    ruleId: f.kind,
    resourceKind: f.subject.kind,
    namespace: f.subject.namespace,
    clusterId: f.subject.clusterId,
    workloadName: f.subject.name,
  };
}

export function buildInfrastructureListener(attacher: EvidenceAttacher): Array<{
  topic: string;
  handler: EventHandler;
}> {
  const runtimeRiskHandler: EventHandler = async (envelope: EventEnvelope<unknown>) => {
    if (envelope.type !== EventTypes.RUNTIME_RISK_DETECTED) return;
    const payload = envelope.data as RuntimeRiskDetectedPayload;
    for (const finding of payload?.findings ?? []) {
      if (!finding?.id) continue;
      const input = fromRuntimeRisk(envelope.tenantId, finding);
      await attacher.attachInfrastructureFinding({
        tenantId: envelope.tenantId,
        input,
        finding,
        sourceLabel: 'runtime-risk',
      });
    }
  };

  const healthIssueHandler: EventHandler = async (envelope: EventEnvelope<unknown>) => {
    if (envelope.type !== EventTypes.CLUSTER_HEALTH_ISSUE_DETECTED) return;
    const payload = envelope.data as ClusterHealthIssueDetectedPayload;
    for (const finding of payload?.findings ?? []) {
      if (!finding?.id) continue;
      const input = fromHealthIssue(envelope.tenantId, finding);
      await attacher.attachInfrastructureFinding({
        tenantId: envelope.tenantId,
        input,
        finding,
        sourceLabel: 'health-issue',
      });
    }
  };

  return [
    { topic: EventTypes.RUNTIME_RISK_DETECTED, handler: runtimeRiskHandler },
    { topic: EventTypes.CLUSTER_HEALTH_ISSUE_DETECTED, handler: healthIssueHandler },
  ];
}
