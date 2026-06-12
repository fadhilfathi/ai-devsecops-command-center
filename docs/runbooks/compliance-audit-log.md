# Compliance Audit Log — `AuditLogEmissionErrorRate` Runbook

> **Owner:** ComplianceOfficer (S2.9 owner)
> **Alert:** `AuditLogEmissionErrorRate` in `security_stack.audit_emission` group
> **Severity:** P2 (ticket on >0.1/s for 5m; **page** on >1/s for 5m)
> **SLO:** see `docs/observability/slos-security-stack.md` §4.2
> **Source of truth for the metric:** S2.9 §18 — `docs/compliance/evidence-collection.md` §18.1 (architecture) and §18.5 (event taxonomy)

## One-liner triage

> **If `audit_log_emission_total{result="error"}` rate exceeds threshold,
> check (1) the bus connection, (2) the schema validation, (3) the
> structured log filter for the audit kind.**

These are the three independent failure modes the S2.9 audit emission
helpers are designed to surface, in the order they should be ruled out.
They map 1:1 to the `withAudit()` wrapper in
`backend/services/compliance/src/observability/audit.ts`.

## Why this alert exists

The S2.9 POA&M audit log is the **system-of-record** for compliance
state changes (`poam.created`, `poam.closed`, `poam.overdue`,
`poam.in_progress`, `poam.pending_verification`, `poam.risk_accepted`,
`evidence.attached`, `control.updated`, `control.violated`). An
emission failure means a security-relevant state change is silently
lost — a **compliance regression** (CIS 8.11, NIST AU-2/AU-3), not a
runtime blip. Treat P2 page-on-rate as a compliance incident until
proven otherwise.

The 99%/30d success SLO is the integrity guardrail: ≤ 1% error rate
over 30 days means at most 1 audit record in 100 is silently dropped.
Going above 1% over 5m triggers the alert.

## Symptom

- Alertmanager page or ticket:
  `AuditLogEmissionErrorRate: rate(audit_log_emission_total{result="error"}[5m])`
  above threshold for 5m.
- `compliance-service` `/metrics` endpoint shows
  `audit_log_emission_total{service="compliance-service",result="error"}`
  is rising in step with the alert.

## Decision tree

```
1. Bus connection
   └─ Is the event bus reachable from compliance-service?
      ├─ No  → fix bus connectivity (see §1.1). Audit emission will
      │         recover automatically once `withAudit` can publish.
      │         The failed events are NOT retried — they are
      │         intentionally lost (no double-write to audit_log).
      │         Follow the "Backfill" procedure in §1.2 if the outage
      │         was > 5min and covered active control violations.
      └─ Yes → continue.

2. Schema validation
   └─ Are the failing events rejected by the bus's envelope/payload
      schema validator?
      ├─ Yes → see §2.1 for the validator contract. The most common
      │         cause in S2.9 is a `detail` field with a non-serializable
      │         value (BigInt, circular ref) inside the `recordAudit`
      │         structured log. Strip the offending `detail` and ship
      │         a fix; the `audit_kind` in the error log tells you
      │         which emission site.
      └─ No  → continue.

3. Structured log filter for the audit kind
   └─ Is the structured log filter on the consumer side
      (`event="audit_log.record"`) dropping the record?
      ├─ Yes → see §3.1. The filter is intentional and aligns with
      │         the `audit_kind` → `retention_class` mapping in
      │         `docs/compliance/evidence-collection.md` §18.5.
      │         If the `audit_kind` is `control.violated` and the
      │         filter is dropping it, the SIEM/GRC consumer is
      │         misconfigured — fix the consumer, not the emitter.
      └─ No  → escalate (see "Escalation" below).
```

## Detail

### 1.1 Bus connectivity check

- From the compliance-service pod, `curl` the bus health endpoint
  (RabbitMQ `/api/aliveness-test/<vhost>`, NATS `GET /healthz`,
  Kafka broker liveness — whichever the deployment uses).
- Check `devsecops_eventbus_lag_seconds` (SLO §4): if lag is also
  elevated, the bus is the root cause and this runbook is downstream
  of `EventBusLagBreach`.
- Check compliance-service pod logs for `EventBusPublishError` or
  `bus.publish timeout` around the alert window. The `withAudit`
  helper logs the underlying error in the `detail.error` field of the
  structured `audit_log.record` line.

### 1.2 Backfill (only if outage > 5min AND active violations)

`withAudit` does **not** retry failed emissions by design — duplicate
emission would corrupt the audit hash chain. Backfill must be a
**manual SQL insert** by the on-call DBA, after the alert clears,
using the structured `audit_log.record` lines that WERE successfully
written (every failed emission logs the record before throwing). Do
not attempt automated backfill.

### 2.1 Schema validation contract

The bus validates two things before accepting an emission:

1. `EventEnvelope<T>` shape (`eventId`, `occurredAt`, `tenantId`,
   `source`, `type`, `subject`, `data`).
2. Per-`type` payload Zod schema from `EventTypes` in
   `@aicc/shared/events` (the 6 compliance events defined in
   S2.9 §18.5).

If schema validation fails, the bus returns a 4xx-equivalent to
`withAudit`, which catches and records with `result="error"`,
`detail.error` containing the Zod issue path. The `audit_kind` in
that log line tells you which S2.9 emit site broke — match against
the 11 `audit_kind` values in `audit.ts`.

### 3.1 Structured log filter for the audit kind

The `audit_log.record` structured log line uses a stable
`event="audit_log.record"` and a stable `audit_kind` field. The
SIEM/GRC consumer subscribes via that filter. If the filter is
dropping records:

- Verify the consumer is matching on `audit_kind`, not on
  `event.type` (a common S2.9 integration bug — `event.type` is the
  CloudEvents-style name like `compliance.poam.created`, NOT the
  `audit_kind` like `poam.created`).
- The 11-value `audit_kind` union is the SLO-relevant label, not the
  event type. See the `audit_kind` → `retention_class` table in
  `evidence-collection.md` §18.5.

## Code locations

- `backend/services/compliance/src/observability/audit.ts` —
  `recordAudit()` and `withAudit()` helpers, `metricsRegistry`,
  `AuditKind` union.
- `backend/services/compliance/src/poam/poam.service.ts` — POA&M
  emission sites (5 audit kinds).
- `backend/services/compliance/src/evidence/evidence-attacher.ts` —
  control/evidence emission sites (2 audit kinds).
- `backend/services/compliance/src/index.ts` — `/metrics` endpoint
  (Prometheus text format).

## Escalation

If the decision tree does not resolve within 15 minutes, escalate to:

1. ComplianceOfficer (slot `019ebae2-9e0c-7981-ba99-225c9c32226d`) —
   S2.9 owner.
2. SREEngineer (slot `019ebae2-9e02-7e01-9b2b-451eb0d20f59`) — alert
   infrastructure.
3. SecurityArchitect (slot `019ebae2-9df5-7c30-a6f0-2b379c4f0a4c`) —
   if a control violation was silently lost, the integrity claim
   for that audit gap must be reassessed before S2.8 sign-off
   (per the §3.6 audit log schema).

## Cross-references

- **SLO contract:** `docs/observability/slos-security-stack.md` §4.2
- **S2.9 POA&M + audit emission architecture & lifecycle:**
  `docs/compliance/evidence-collection.md` §18 (Auto-mapping CVEs to
  controls)
- **S2.8 audit log schema (downstream consumer):**
  `docs/security/s2-security-mitigations.md` §3.6
- **Alert rule source:** `infra/observability/prometheus/alert-rules.yml`
  — group `security_stack.audit_emission`
