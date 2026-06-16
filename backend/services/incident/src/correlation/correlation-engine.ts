/**
 * AI Incident Correlation Engine — Sprint 4.
 *
 * Extends the Sprint 1 / 2 event correlation (handled by
 * `listeners/index.ts`) with a full *causal* correlation engine
 * that produces an ordered chain of correlated findings:
 *
 *   Critical CVE
 *     ↓
 *   Failed Build
 *     ↓
 *   Deployment Blocked
 *     ↓
 *   Manual Override
 *     ↓
 *   Cluster Incident
 *     ↓
 *   Root Cause Chain
 *
 * The engine consumes the unified event stream (security
 * findings, SBOM findings, CI/CD failures, Kubernetes events,
 * infrastructure findings, deployment events, incident
 * reports) and produces:
 *
 *   - a list of `IncidentChain` (one per detected root cause)
 *   - a list of `IncidentCorrelation` (the edges that
 *     participate in those chains)
 *
 * In Sprint 4 the engine is pure / in-process. The Sprint 5
 * refactor will lift it into a dedicated correlation service.
 */
import { randomUUID } from 'node:crypto';
import type { EventEnvelope, UUID, Severity } from '@aicc/shared';
import { EventTypes } from '@aicc/shared';

export type CorrelationEventType =
  | 'security.finding'
  | 'sbom.finding'
  | 'cicd.build.failed'
  | 'cicd.deployment.blocked'
  | 'cicd.deployment.manual_override'
  | 'k8s.event'
  | 'infrastructure.finding'
  | 'deployment.event'
  | 'incident.report'
  | 'health.recommendation'
  | 'runtime.risk'
  | 'unknown';

export interface CorrelationEvent {
  id: string;
  type: CorrelationEventType;
  occurredAt: string;
  tenantId: UUID;
  severity: Severity;
  /** Stable key used to correlate events that share a subject. */
  correlationKey: string;
  /** Display subject — namespace/workload/pod/CVE/etc. */
  subject: string;
  message: string;
  /** Free-form payload (CVE id, image digest, etc.). */
  data: Record<string, unknown>;
  /** Pointer to the source event envelope. */
  source: { eventId: UUID; type: string };
}

export interface CorrelationEdge {
  id: string;
  source: string;
  target: string;
  /** The relation class between two events. */
  kind: 'caused_by' | 'preceded_by' | 'mitigated_by' | 'correlated_with';
  weight: number;
  rationale: string;
}

export interface IncidentChain {
  id: string;
  tenantId: UUID;
  rootEventId: string;
  /** Ordered list of event ids, root → leaf. */
  eventIds: string[];
  /** Causal edges between events in the chain. */
  edges: CorrelationEdge[];
  /** Highest severity across the chain. */
  severity: Severity;
  title: string;
  summary: string;
  createdAt: string;
}

export interface CorrelationEngine {
  /** Convert a raw event envelope into a normalised CorrelationEvent. */
  normalise(event: EventEnvelope): CorrelationEvent | undefined;
  /** Build chains for a stream of events. Pure, deterministic. */
  correlate(events: CorrelationEvent[]): { chains: IncidentChain[]; edges: CorrelationEdge[] };
  /** Find a chain by id. */
  findChain(chains: IncidentChain[], id: string): IncidentChain | undefined;
}

/** Mapping from raw event type → correlation event type. */
function mapType(rawType: string): CorrelationEventType {
  switch (rawType) {
    case EventTypes.VULNERABILITY_DETECTED:
    case EventTypes.SCAN_COMPLETED:
    case 'security.finding':
      return 'security.finding';
    case 'sbom.finding':
    case 'sbom.vulnerability':
      return 'sbom.finding';
    case 'cicd.build.failed':
    case 'build.failed':
    case 'pipeline.failed':
      return 'cicd.build.failed';
    case 'cicd.deployment.blocked':
    case 'deployment.blocked':
    case 'policy.violation':
      return 'cicd.deployment.blocked';
    case 'cicd.deployment.manual_override':
    case 'deployment.override':
      return 'cicd.deployment.manual_override';
    case 'k8s.event':
    case 'k8s.pod.warning':
    case 'k8s.deployment.failed':
      return 'k8s.event';
    case 'infrastructure.finding':
    case 'cost.finding':
      return 'infrastructure.finding';
    case 'deployment.event':
    case 'deployment.succeeded':
    case 'deployment.started':
      return 'deployment.event';
    case EventTypes.INCIDENT_CREATED:
    case EventTypes.INCIDENT_RESOLVED:
    case 'incident.report':
      return 'incident.report';
    case 'health.recommendation':
      return 'health.recommendation';
    case 'runtime.risk':
      return 'runtime.risk';
    default:
      return 'unknown';
  }
}

/**
 * Build the *correlation key* — the field used to glue events
 * that share a subject (same CVE id, same workload, same
 * deployment, same pod, same cluster).
 *
 * Key precedence: cveId > imageDigest > workload > pod > namespace > cluster
 */
function buildCorrelationKey(data: Record<string, unknown>): { key: string; subject: string } {
  if (typeof data.cveId === 'string') {
    return { key: `cve:${data.cveId}`, subject: `CVE ${data.cveId}` };
  }
  if (typeof data.imageDigest === 'string') {
    return { key: `image:${data.imageDigest}`, subject: `image ${String(data.imageDigest).slice(0, 19)}…` };
  }
  if (typeof data.image === 'string') {
    return { key: `image:${data.image}`, subject: `image ${data.image}` };
  }
  if (typeof data.workload === 'string' && typeof data.namespace === 'string') {
    return { key: `workload:${data.namespace}/${data.workload}`, subject: `${data.namespace}/${data.workload}` };
  }
  if (typeof data.deployment === 'string' && typeof data.namespace === 'string') {
    return { key: `workload:${data.namespace}/${data.deployment}`, subject: `${data.namespace}/${data.deployment}` };
  }
  if (typeof data.pod === 'string' && typeof data.namespace === 'string') {
    return { key: `pod:${data.namespace}/${data.pod}`, subject: `pod ${data.namespace}/${data.pod}` };
  }
  if (typeof data.namespace === 'string') {
    return { key: `ns:${data.namespace}`, subject: `namespace ${data.namespace}` };
  }
  if (typeof data.clusterId === 'string') {
    return { key: `cluster:${data.clusterId}`, subject: `cluster ${data.clusterId}` };
  }
  if (typeof data.subject === 'string') {
    return { key: `subject:${data.subject}`, subject: data.subject };
  }
  return { key: 'unknown', subject: 'unknown' };
}

/** Causal ordering: which event types can CAUSE which others. */
const CAUSAL_ORDER: Record<CorrelationEventType, number> = {
  'security.finding': 1,
  'sbom.finding': 1,
  'runtime.risk': 1,
  'cicd.build.failed': 2,
  'cicd.deployment.blocked': 3,
  'cicd.deployment.manual_override': 4,
  'k8s.event': 5,
  'infrastructure.finding': 5,
  'health.recommendation': 5,
  'deployment.event': 4,
  'incident.report': 6,
  'unknown': 99,
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1, unknown: 0,
};

function highestSeverity(events: CorrelationEvent[]): Severity {
  let best: Severity = 'unknown';
  for (const e of events) {
    if (SEVERITY_RANK[e.severity] > SEVERITY_RANK[best]) best = e.severity;
  }
  return best;
}

function chainTitle(events: CorrelationEvent[]): string {
  const types = Array.from(new Set(events.map((e) => e.type)));
  const root = events.find((e) => e.type === 'security.finding' || e.type === 'sbom.finding') ?? events[0];
  if (!root) return 'Incident chain';
  return `Incident: ${root.subject} (${types.join(' → ')})`;
}

function chainSummary(events: CorrelationEvent[], edges: CorrelationEdge[]): string {
  const order = [...events].sort((a, b) => CAUSAL_ORDER[a.type] - CAUSAL_ORDER[b.type] || a.occurredAt.localeCompare(b.occurredAt));
  return order.map((e) => `• ${new Date(e.occurredAt).toISOString()}  ${e.type} — ${e.message}`).join('\n')
    + (edges.length ? `\n${edges.length} causal edge(s) identified.` : '');
}

export function buildCorrelationEngine(): CorrelationEngine {
  return {
    normalise(event) {
      const data = (event.data ?? {}) as Record<string, unknown>;
      const { key, subject } = buildCorrelationKey(data);
      return {
        id: randomUUID(),
        type: mapType(event.type),
        occurredAt: event.occurredAt,
        tenantId: event.tenantId,
        severity: event.severity ?? 'unknown',
        correlationKey: key,
        subject,
        message: typeof data.message === 'string' ? data.message : `${event.type} on ${subject}`,
        data,
        source: { eventId: event.eventId, type: event.type },
      };
    },

    correlate(events) {
      // Bucket by correlation key. Each bucket is a candidate chain.
      const buckets = new Map<string, CorrelationEvent[]>();
      for (const e of events) {
        const arr = buckets.get(e.correlationKey) ?? [];
        arr.push(e);
        buckets.set(e.correlationKey, arr);
      }
      const chains: IncidentChain[] = [];
      const edges: CorrelationEdge[] = [];
      for (const [key, group] of buckets.entries()) {
        if (group.length < 2) continue;
        // Sort by causal order, then by occurredAt.
        const ordered = [...group].sort((a, b) => CAUSAL_ORDER[a.type] - CAUSAL_ORDER[b.type] || a.occurredAt.localeCompare(b.occurredAt));
        const chainEdges: CorrelationEdge[] = [];
        for (let i = 1; i < ordered.length; i++) {
          const src = ordered[i - 1]!;
          const tgt = ordered[i]!;
          const kind: CorrelationEdge['kind'] = CAUSAL_ORDER[src.type] < CAUSAL_ORDER[tgt.type] ? 'caused_by' : 'preceded_by';
          const weight = Math.abs(CAUSAL_ORDER[tgt.type] - CAUSAL_ORDER[src.type]);
          const edge: CorrelationEdge = {
            id: randomUUID(),
            source: src.id,
            target: tgt.id,
            kind,
            weight,
            rationale: `${src.type} → ${tgt.type}`,
          };
          chainEdges.push(edge);
          edges.push(edge);
        }
        chains.push({
          id: randomUUID(),
          tenantId: ordered[0]!.tenantId,
          rootEventId: ordered[0]!.id,
          eventIds: ordered.map((e) => e.id),
          edges: chainEdges,
          severity: highestSeverity(ordered),
          title: chainTitle(ordered),
          summary: chainSummary(ordered, chainEdges),
          createdAt: new Date().toISOString(),
        });
        void key;
      }
      return { chains, edges };
    },

    findChain(chains, id) {
      return chains.find((c) => c.id === id);
    },
  };
}
