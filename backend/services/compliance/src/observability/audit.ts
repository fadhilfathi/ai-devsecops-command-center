// Compliance service observability — audit log emission.
//
// Per the S2.7 + S2.9 alignment with SREEngineer (path (b) — direct /metrics
// emission via prom-client):
//
//   - One Counter `audit_log_emission_total{service, result}` is exposed on
//     the local `metricsRegistry`. The /metrics route in src/index.ts flushes
//     this registry in the standard Prometheus text format.
//
//   - Every state change in the service (poam created / closed / overdue /
//     risk-accepted / in_progress / pending_verification, evidence attached,
//     control violated, control updated) calls `recordAudit(...)` in the
//     same call frame as the bus.publish() that emits the corresponding
//     event. If publish succeeds, the counter is incremented with
//     `result: 'success'`; if it throws, `result: 'error'`. The structured
//     log line is emitted in both cases as the legal audit trail.
//
// Cardinality: 1 service × 2 result = 2 series. Negligible.
//
// TODO(sre): When the shared @aicc/observability package lands (task
// 019ebbea…), replace the local Registry with `metricsRegistry` re-exported
// from there. The `recordAudit` signature is the public surface; the
// underlying counter can move to a different registry without breaking
// call sites.

import { Counter, Registry } from 'prom-client';
import { randomUUID } from 'node:crypto';

import { createLogger } from '@aicc/shared/logger';

const log = createLogger({ service: 'compliance-service', level: 'info' });

// ---------------------------------------------------------------------------
// Local Prometheus registry (one per service process).
// Flushed by the /metrics route in src/index.ts.
// ---------------------------------------------------------------------------

export const metricsRegistry = new Registry();

// Default process metrics (event-loop lag, GC, RSS, FD count) — these come
// for free and are part of the S2.7 baseline.
import { collectDefaultMetrics } from 'prom-client';
collectDefaultMetrics({ register: metricsRegistry, prefix: 'compliance_service_' });

// ---------------------------------------------------------------------------
// The single canonical SLO counter for audit emission.
// ---------------------------------------------------------------------------

export const auditLogEmission = new Counter({
  name: 'audit_log_emission_total',
  help: 'Compliance audit log records emitted to the audit pipeline. Result is success or error.',
  labelNames: ['service', 'result'] as const,
  registers: [metricsRegistry],
});

// ---------------------------------------------------------------------------
// Audit record surface
// ---------------------------------------------------------------------------

export type AuditResult = 'success' | 'error';

export type AuditKind =
  // POA&M lifecycle
  | 'poam.created'
  | 'poam.in_progress'
  | 'poam.pending_verification'
  | 'poam.closed'
  | 'poam.overdue'
  | 'poam.risk_accepted'
  // Evidence
  | 'evidence.attached'
  // Control posture
  | 'control.updated'
  | 'control.violated';

export interface AuditRecord {
  /** Tenant the audit record belongs to. */
  tenantId: string;
  /** Outcome of the bus.publish() call. */
  result: AuditResult;
  /** Logical kind of the state change. */
  auditKind: AuditKind;
  /** Subject id (controlId, poamId, evidenceId, etc.). */
  subjectId: string;
  /** Optional detail merged into the structured log. Not a label. */
  detail?: Record<string, unknown>;
  /** Optional trace id; if absent, the audit_id is reused. */
  traceId?: string;
}

// ---------------------------------------------------------------------------
// recordAudit — the single emission point.
// ---------------------------------------------------------------------------

/**
 * Increment the audit_log_emission_total counter and emit the structured
 * log line. Always safe to call (never throws). Call this in the same try /
 * catch frame as bus.publish() so the counter reflects actual emission
 * success.
 */
export function recordAudit(record: AuditRecord): void {
  const auditId = randomUUID();
  const ts = new Date().toISOString();
  const level = record.result === 'error' ? 'error' : 'info';

  // 1. Counter (Prometheus path). The Counter#inc call cannot throw on
  // valid label strings; we still wrap in try/catch for paranoia.
  try {
    auditLogEmission.inc({ service: 'compliance-service', result: record.result });
  } catch (err) {
    log.error({ err, auditKind: record.auditKind, subjectId: record.subjectId }, 'audit counter inc failed');
  }

  // 2. Structured log line (the audit trail). Shape is locked with SRE per
  // the S2.7 + S2.9 thread.
  const payload = {
    event: 'audit_log.record',
    service: 'compliance-service',
    tenantId: record.tenantId,
    result: record.result,
    audit_kind: record.auditKind,
    audit_id: auditId,
    trace_id: record.traceId ?? auditId,
    subject_id: record.subjectId,
    detail: record.detail,
    ts,
  };
  if (level === 'error') {
    log.error(payload, `audit_log.record: ${record.auditKind}`);
  } else {
    log.info(payload, `audit_log.record: ${record.auditKind}`);
  }
}

/**
 * Convenience helper: wrap an async bus.publish() call with the audit
 * emission. Returns the original promise's resolved value, or rethrows the
 * rejected error after recording the error counter.
 *
 * Usage:
 *   try {
 *     await withAudit({ tenantId, auditKind: 'poam.created', subjectId: poam.id, detail: {...} },
 *       () => this.bus.publish(envelope));
 *   } catch (err) {
 *     // publish failed; counter and log already recorded
 *     throw err;
 *   }
 */
export async function withAudit<T>(record: Omit<AuditRecord, 'result'>, fn: () => Promise<T>): Promise<T> {
  try {
    const out = await fn();
    recordAudit({ ...record, result: 'success' });
    return out;
  } catch (err) {
    recordAudit({ ...record, result: 'error', detail: { ...record.detail, error: String(err) } });
    throw err;
  }
}
