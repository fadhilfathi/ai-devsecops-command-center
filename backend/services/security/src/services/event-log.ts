/**
 * In-process event log for the security-service.
 *
 * Sprint 2 stub: subscribes to all SECURITY_TOPICS and stores the most
 * recent 200 events per tenant for the dashboard's "recent activity" feed.
 *
 * Sprint 2.1 plan: replace with a Redis Streams consumer that reads from
 * a `aicc.security.activity` stream and persists the last 1000 events
 * per tenant.
 */
import type { EventBus, EventEnvelope } from '@aicc/shared';
import {
  SBOM_TOPIC,
  VULN_TOPIC,
  RISK_TOPIC,
} from '@aicc/shared/security';
import type { RecentActivityEntry } from '@aicc/shared/security';

const MAX_EVENTS_PER_TENANT = 200;
const CAP = 1000;

export interface SecurityEventRecord {
  id: string;
  type: string;
  timestamp: string;
  summary: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  payload: Record<string, unknown>;
  tenantId: string;
  eventTypeToDashboardType(type: string): RecentActivityEntry['type'];
}

export class InMemoryEventLog {
  private byTenant = new Map<string, SecurityEventRecord[]>();

  constructor(bus: EventBus) {
    void bus.subscribe(SBOM_TOPIC, (e) => { this.record(e); });
    void bus.subscribe(VULN_TOPIC, (e) => { this.record(e); });
    void bus.subscribe(RISK_TOPIC, (e) => { this.record(e); });
  }

  private record(e: EventEnvelope): void {
    const rec: SecurityEventRecord = {
      id: e.eventId,
      type: e.type,
      timestamp: e.occurredAt,
      summary: this.summarise(e),
      severity: this.severityFor(e),
      payload: (e.data ?? {}) as Record<string, unknown>,
      tenantId: e.tenantId,
      eventTypeToDashboardType: this.eventTypeToDashboardType,
    };
    const list = this.byTenant.get(e.tenantId) ?? [];
    list.unshift(rec);
    if (list.length > MAX_EVENTS_PER_TENANT) list.length = MAX_EVENTS_PER_TENANT;
    this.byTenant.set(e.tenantId, list);
    // LRU-ish cap so a runaway tenant doesn't OOM the process
    if (this.byTenant.size > CAP) {
      const oldestKey = this.byTenant.keys().next().value;
      if (oldestKey) this.byTenant.delete(oldestKey);
    }
  }

  list(tenantId: string, limit = 20): SecurityEventRecord[] {
    return (this.byTenant.get(tenantId) ?? []).slice(0, limit);
  }

  private summarise(e: EventEnvelope): string {
    switch (e.type) {
      case SBOM_TOPIC: {
        const d = (e.data ?? {}) as { componentCount?: number; rootBomRef?: string };
        return `SBOM generated: ${d.rootBomRef ?? 'unknown'} (${d.componentCount ?? 0} components)`;
      }
      case VULN_TOPIC: {
        const d = (e.data ?? {}) as { vulnerabilityId?: string; severity?: string };
        return `Vulnerability ${d.vulnerabilityId ?? 'unknown'} (${d.severity ?? 'unknown'}) detected`;
      }
      case RISK_TOPIC: {
        const d = (e.data ?? {}) as { subjectId?: string; compositeScore?: number };
        return `Risk score ${d.compositeScore ?? 0} computed for ${d.subjectId ?? 'unknown'}`;
      }
      default:
        return e.type;
    }
  }

  private severityFor(e: EventEnvelope): SecurityEventRecord['severity'] {
    if (!e.severity) return undefined;
    if (e.severity === 'critical' || e.severity === 'high' || e.severity === 'medium' ||
        e.severity === 'low' || e.severity === 'info') return e.severity;
    return undefined;
  }

  private eventTypeToDashboardType(type: string): RecentActivityEntry['type'] {
    if (type === SBOM_TOPIC) return 'sbom.generated';
    if (type === VULN_TOPIC) return 'vulnerability.detected';
    if (type === RISK_TOPIC) return 'risk.calculated';
    return 'sbom.generated'; // safe default
  }
}
