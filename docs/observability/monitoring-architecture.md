# Monitoring, Logging & Metrics Architecture

> **Sprint:** 1 — Foundations
> **Owner:** SREEngineer
> **Status:** Draft v1.0
> **Last Updated:** 2026-06-12
> **Related Docs:** [`../architecture/system-architecture.md`](../architecture/system-architecture.md), [`../architecture/event-bus.md`](../architecture/event-bus.md), [`../architecture/security-model.md`](../architecture/security-model.md)

---

## 1. Executive Summary

This document defines the end-to-end **observability architecture** for the AI-DevSecOps Command Center. It establishes the three pillars — **metrics, logs, and traces** — on top of an **OpenTelemetry-first** instrumentation model, with **Prometheus**, **Loki**, and **Tempo** as the primary backends, and **Grafana** as the unified visualization and alerting surface.

The architecture is designed to meet four business goals:

1. **Detect** security, reliability, and performance incidents before users do.
2. **Diagnose** cross-service and agent-to-agent issues in minutes, not hours.
3. **Prove** SLO compliance for internal stakeholders and external auditors.
4. **Scale** observability cost sub-linearly as the platform grows from 6 services to 60+.

All services are required to emit telemetry in the formats defined here. The platform refuses to deploy services that do not expose the standard health, metrics, and tracing endpoints.

---

## 2. Design Principles

| # | Principle | Why it matters |
|---|-----------|----------------|
| 1 | **OpenTelemetry first** | Vendor-neutral SDK; no lock-in to a single backend. |
| 2 | **Structured from the source** | Logs, metrics, and traces share the same `trace_id` / `span_id` context. |
| 3 | **Instrument once, emit many** | Auto-instrumentation in OTel SDK; manual only for business KPIs. |
| 4 | **Cardinality is a budget** | Bounded label cardinality enforced via CI lint rules. |
| 5 | **PII never leaves the process unredacted** | Redaction at SDK boundary, not at log storage. |
| 6 | **SLOs drive alerts** | Page on user-impacting symptoms, not on every threshold trip. |
| 7 | **Observability is a product** | Dashboards, runbooks, and SLOs are versioned and reviewed quarterly. |

---

## 3. The Three Pillars

```
                    +-----------------------+
                    |   Grafana (Unified)   |
                    |  Dashboards / Alerts  |
                    +-----------+-----------+
                                |
            +-------------------+-------------------+
            |                   |                   |
            v                   v                   v
   +-----------------+  +-----------------+  +-----------------+
   |   Prometheus    |  |      Loki       |  |     Tempo       |
   |  (Metrics)      |  |    (Logs)       |  |   (Traces)      |
   +--------+--------+  +--------+--------+  +--------+--------+
            |                    |                    |
            +--------+ +---------+ +---------+-------+
                     | |                   |
                     v v                   v
              +--------------------------+
              |  OpenTelemetry Collector |
              |  (gateway / sidecar)     |
              +--------------------------+
                               |
              +----------------+----------------+
              |  6 Backend Services + Agents  |
              |  (Auth, Agent, Security, ...)|
              +--------------------------------+
```

**Why an OTel Collector in the middle?**
- Decouples application SDK from backend choice.
- Centralized tail-based sampling, PII redaction, and enrichment.
- Single point of egress control (egress firewall, mTLS to backends).

---

## 4. Metrics Architecture

### 4.1 Protocols & Standards

- **Exposition format:** OpenMetrics 1.0 (text-based, Prometheus-compatible).
- **Transport:** HTTP `GET /metrics` for pull (default), OTLP push via Collector for high-fanout workloads.
- **Naming:** `<namespace>_<subsystem>_<unit>_<suffix>` (e.g., `http_server_request_duration_seconds_bucket`).
- **Labels:** snake_case, bounded cardinality, never include PII or unbounded identifiers (no `user_id`, no `email`).

### 4.2 Frameworks

We use **two complementary methodologies** depending on the layer:

#### RED Method (Request-driven services — all 6 backend services)
For every public endpoint, expose:
- **R**ate — `http_server_requests_per_second{service, route, method, status}`
- **E**rrors — `http_server_requests_failed_total{service, route, method, status_class}`
- **D**uration — `http_server_request_duration_seconds{service, route, method, quantile=...}`

#### USE Method (Resources — DB, Redis/NATS, CPU, memory)
For every resource, expose:
- **U**tilization — `redis_connections_in_use / redis_connections_max`
- **S**aturation — `redis_events_blocked_clients`, `nodejs_eventloop_lag_seconds`
- **E**rrors — `redis_command_errors_total{command, error_type}`

#### Agent-Specific Metrics
Each agent (orchestrator, scanner, analyst, remediator) additionally exposes:
- `agent_task_duration_seconds{agent, task_type, outcome}` — histogram
- `agent_tasks_in_flight{agent}` — gauge
- `agent_tasks_total{agent, task_type, outcome}` — counter
- `agent_llm_tokens_total{agent, model, direction}` — counter (input/output)
- `agent_tool_invocations_total{agent, tool, outcome}` — counter
- `agent_decision_confidence{agent, decision_type}` — summary

#### Business KPIs
Curated, low-cardinality, owned by product:
- `security_findings_total{severity, scanner, status}` (open/closed)
- `incidents_total{severity, source, status}`
- `sbom_artifacts_generated_total{ecosystem}`
- `compliance_controls_passing_total{framework, control}`

### 4.3 Cardinality Budget

Hard ceilings enforced by a CI lint (see `infra/observability/prometheus/cardinality-lint.md`):

| Metric family                          | Max unique label combinations |
|----------------------------------------|-------------------------------|
| `http_server_requests_*` (per service) | 50,000                        |
| `agent_task_*` (per agent)             | 10,000                        |
| `security_findings_total`              | 1,000                         |
| `*_llm_tokens_total`                   | 5,000                         |
| Anything else                          | 1,000 (default)               |

PRs introducing a metric above the budget must be approved by SRE and split or aggregated.

### 4.4 Prometheus Topology

Two-tier Prometheus is used:

```
                +----------------------------+
                |  Global Prometheus (HA)    |
                |  Federation:               |
                |  job: federation           |
                |  scrape_interval: 60s      |
                +-------------+--------------+
                              ^
                              |  /federate
                              |
        +---------------------+----------------------+
        |                                            |
+-------+------------+                  +------------+--------+
| Regional Prom (EU)  |                  | Regional Prom (US) |
| short retention 7d  |                  | short retention 7d |
| scrape_interval 15s |                  | scrape_interval 15s|
+----------------------+                  +--------------------+
        ^                                            ^
        |  /metrics                                  |  /metrics
        |                                            |
  +-----+----+  +-----+----+  +-----+----+     (same for US)
  |  Auth   |  |  Agent   |  | Security |
  +---------+  +---------+  +----------+
```

- **Regional Prometheus** — full resolution, 7-day retention, used for live alerting.
- **Global Prometheus** — federated aggregates (`sum by (service)(rate(...))`), 13-month retention for SLO reporting and compliance.
- **Long-term storage** — Thanos sidecar or Mimir for object-store-backed retention (decision in §10).

### 4.5 Service-Level Indicators (SLIs) & Objectives (SLOs)

Each backend service must declare its SLOs in a machine-readable file: `services/<name>/slo.yaml`.

Example (Auth service):
```yaml
service: auth
slis:
  availability:
    description: "Successful non-5xx responses / total responses"
    query: sum(rate(http_server_requests_total{service="auth",status!~"5.."}[5m]))
           / sum(rate(http_server_requests_total{service="auth"}[5m]))
  latency:
    description: "p99 of /token endpoint under 250ms"
    query: histogram_quantile(0.99, sum by (le) (rate(http_server_request_duration_seconds_bucket{service="auth",route="/token"}[5m])))
  correctness:
    description: "JWT validation error rate"
    query: sum(rate(jwt_validation_failures_total[5m]))
           / sum(rate(jwt_validations_total[5m]))
slos:
  - sli: availability
    target: 0.999        # 99.9% over 30d rolling window
    window: 30d
  - sli: latency
    target: 0.95         # 95% of requests < 250ms
    window: 30d
  - sli: correctness
    target: 0.9999       # 99.99% valid token validations
    window: 30d
error_budget_policy: ./policies/error-budget.md
```

The **error budget** for the slowest-burning SLO governs the deployment freeze threshold (see §6.4).

---

## 5. Logging Architecture

### 5.1 Format

- **Encoding:** newline-delimited JSON (NDJSON), UTF-8.
- **Schema (enforced by JSON Schema in `infra/observability/logs/log-schema.json`):**

| Field        | Type    | Required | Notes                                                  |
|--------------|---------|----------|--------------------------------------------------------|
| `timestamp`  | string  | yes      | RFC 3339, UTC, microsecond precision                   |
| `level`      | string  | yes      | `debug` \| `info` \| `warn` \| `error` \| `fatal`      |
| `service`    | string  | yes      | Logical service name (matches Prometheus `service` label) |
| `version`    | string  | yes      | Semver of the emitting binary                          |
| `env`        | string  | yes      | `dev` \| `staging` \| `prod`                           |
| `trace_id`   | string  | when avail| 32-hex from W3C `traceparent`                          |
| `span_id`    | string  | when avail| 16-hex from W3C `traceparent`                          |
| `tenant_id`  | string  | yes      | Multi-tenant boundary tag                              |
| `user_id`    | string  | when avail| Hashed; never plaintext email                         |
| `message`    | string  | yes      | Human-readable, templated (no string concat)           |
| `context`    | object  | no       | Arbitrary structured data, max 4 KB serialized        |
| `error.type` | string  | on error | Exception class name                                   |
| `error.stack`| string  | on error | Stack trace, truncated to 4 KB                         |

### 5.2 Levels

| Level   | Volume target (% of total) | Use case                                        |
|---------|----------------------------|--------------------------------------------------|
| `error` | < 1%                       | Failures requiring investigation                 |
| `warn`  | 1–5%                       | Recoverable anomalies, deprecations              |
| `info`  | 60–80%                     | Business events: login, scan completed, PR opened |
| `debug` | < 10% (off in prod by default) | Dev-time deep dives                       |

Production runs at `info` by default; `debug` is opt-in per service via dynamic config.

### 5.3 Correlation

Every log line carries `trace_id` and `span_id` when one exists. The OTel SDK populates these automatically. A log without a `trace_id` may be sampled out (see §5.6).

### 5.4 PII & Secret Redaction

Redaction happens at the **SDK boundary**, not at ingestion. Rules:

1. **Email, phone, IP, JWT, bearer tokens** are matched against regex allow-deny and replaced with `[REDACTED:<type>]`.
2. **Known secret patterns** (AWS keys, GitHub tokens, private keys) trigger an immediate alert to SecurityArchitect and the line is dropped entirely.
3. **Free-form `message` fields** are scanned; matches are replaced. Cardinality is preserved via stable hash of the value (HMAC-SHA256 with rotating key).
4. The redactor is unit-tested with a corpus of 200+ fixtures (`infra/observability/logs/redaction-fixtures.json`).

### 5.5 Transport

```
Service stdout (NDJSON)
   |
   v
Fluent Bit (DaemonSet, Kubernetes) OR journald+promtail (bare metal)
   |  parses JSON, enriches with k8s labels, applies redaction safety net
   v
Loki distributor (ingester ring)
   |  chunked, gzip, stored on object storage
   v
Loki queriers / Grafana
```

- **Why Loki for app logs:** cheap, label-indexed, scales horizontally, plays well with Grafana.
- **Why a separate store for audit logs:** audit logs require WORM storage and 7-year retention (see §5.7).

### 5.6 Sampling

- **Error and warn lines** are always retained 100%.
- **Info lines without `trace_id`** are tail-sampled at 1% in prod, 100% in staging.
- **Info lines with `trace_id`** are kept if the trace is kept (see §7.4).
- **Debug** is dropped at the SDK in prod unless a `?debug=1` query param or feature flag is set.

### 5.7 Retention

| Log class       | Hot (Loki)  | Warm (S3/GCS) | Cold / Archive | Compliance basis        |
|-----------------|-------------|---------------|----------------|-------------------------|
| Application     | 14 days     | 90 days       | 1 year         | Operational             |
| Access / audit  | 30 days     | 1 year        | **7 years**    | SOC 2, ISO 27001        |
| Security events | 90 days     | 1 year        | **7 years**    | SOC 2, NIST 800-53 AU   |

Audit logs are written to a **separate append-only stream** (Loki rules push to S3 Object Lock with compliance mode) and indexed in a read-only Grafana data source. ComplianceOfficer owns the retention mapping; see `docs/compliance/audit-retention.md`.

---

## 6. Health Checks & Probes

### 6.1 Probe Endpoints

Every service exposes three probe endpoints on a separate management port (e.g., `:9090`):

| Endpoint   | Purpose                                          | K8s probe         | Response codes       |
|------------|--------------------------------------------------|-------------------|----------------------|
| `/livez`   | "Process is running and not deadlocked"          | `livenessProbe`   | 200 / 503            |
| `/readyz`  | "Process can serve traffic" (deps healthy)       | `readinessProbe`  | 200 / 503            |
| `/startz`  | "Process finished slow initialization"           | `startupProbe`    | 200 / 503            |

### 6.2 Probe Semantics

- **`/livez`** is **shallow** — only fails if the event loop is blocked, the process is OOM-killed, or shutdown was signaled. Never check downstream dependencies here (cascading restarts).
- **`/readyz`** is **deep with timeout** — checks critical dependencies (Postgres, Redis/NATS, vault) with a 250 ms hard timeout per check. The endpoint returns 503 if any check fails OR exceeds the timeout.
- **`/startz`** returns 503 until first successful `/readyz`, then never again.

### 6.3 Standard Probe Payload (deep)

```json
{
  "status": "ok",
  "checks": {
    "postgres":    { "status": "ok", "latency_ms": 4 },
    "redis":       { "status": "ok", "latency_ms": 1 },
    "nats":        { "status": "ok", "latency_ms": 2 },
    "vault":       { "status": "ok", "latency_ms": 18 },
    "config_loaded": { "status": "ok" }
  },
  "version": "1.4.2",
  "uptime_s": 3842
}
```

### 6.4 Error Budget–Aware Deploys

If a service's rolling 30-day error budget is exhausted, the CI/CD pipeline **blocks** further deploys to that service until the budget is restored. The SLO controller surfaces this as a `service_error_budget_remaining` gauge per service; deploy-time policy is enforced by an admission webhook reading this gauge.

---

## 7. Distributed Tracing

### 7.1 Standard

- **W3C Trace Context** is the only trace context format (no B3, no proprietary headers).
- All inbound HTTP servers **must** trust the incoming `traceparent` if it came from a known mTLS peer; otherwise generate a new trace.
- Outbound HTTP clients **must** inject `traceparent` and `tracestate`.

### 7.2 Span Attributes

Every span includes:
- `service.name`, `service.version`, `deployment.environment` (resource attrs)
- `tenant.id` (mandatory)
- For HTTP spans: standard `http.*` semantic conventions
- For DB spans: `db.system`, `db.statement` (sanitized — no bind values), `db.rows_affected`
- For agent spans: `agent.name`, `agent.task.type`, `agent.llm.model`

### 7.3 Span Lifecycle

```
HTTP request -> [server span: gateway]
                  -> [client span: agent svc -> security svc]
                       -> [internal span: vuln scan]
                       -> [internal span: SBOM generate]
                  -> [client span: agent svc -> compliance svc]
```

The agent-orchestrator is responsible for **parenting** all sub-agent work under a single root span per logical task (`task_id`).

### 7.4 Sampling

- **Head-based:** default `parentbased_traceidratio` sampler at 1% in prod, 100% in staging.
- **Tail-based (Collector):** keep 100% of traces that:
  - have any error span
  - exceed p99 latency for the route
  - are flagged as `security.review=true` via span attribute
- **Force-on:** any request with header `x-force-trace: 1` (used by support and SREs).

This yields ~5% effective retention with full coverage of bad outcomes.

### 7.5 Backend

- **Tempo** with object-store backend (S3/GCS), 14-day trace retention.
- **Jaeger UI** is **not** used; Grafana's Tempo datasource provides Explore and trace-to-metrics / trace-to-logs jumps.
- Span volume cap: **50 million spans/day** per environment. Above the cap, head sampling drops to 0.1% and a paging alert fires.

---

## 8. Alerting

### 8.1 Severity Levels

| Severity | Pages?         | Ack SLA | Use case                                      |
|----------|----------------|---------|-----------------------------------------------|
| `page`   | Yes, 24/7      | 5 min   | User-impacting outage or SLO burn alert       |
| `ticket` | No, queue      | 1 day   | Degradation, growing risk, follow-up needed   |
| `info`   | No, dashboard  | n/a     | Awareness only                                |

### 8.2 Alert Anatomy (Go-style)

Every alert rule has:
- **Name:** `ServiceSymptomCondition` (e.g., `AuthHigh5xxRate`).
- **For:** `5m` minimum to avoid flap.
- **Severity:** from the table above.
- **Description:** templated markdown with a Grafana dashboard link and a runbook link.
- **Runbook URL:** required. If absent, the alert is rejected by the linter.

### 8.3 SLO-Based Burn Alerts

We use **multi-window, multi-burn-rate** alerting (Google SRE Workbook, ch. 5):

For a 99.9% SLO over 30 days (43.2 min budget/month):
- **Fast burn (page):** 14.4× burn rate over 1h AND 6h windows. Budget exhausted in ~2 days.
- **Slow burn (ticket):** 1× burn rate over 24h AND 3d windows. Budget exhausted in ~30 days.

The PromQL template lives at `infra/observability/prometheus/templates/slo-burn.yml.j2`.

### 8.4 Routing

```
                    +--------------------+
                    |   Alertmanager     |
                    +---------+----------+
                              |
        +---------------------+----------------------+
        |                     |                      |
        v                     v                      v
  PagerDuty (page)    GitHub Issues (ticket)    Slack #sre-info (info)
        |
        v
  SRE on-call rotation
```

- PagerDuty routes per service via a per-team escalation policy.
- Tickets auto-assign to the service's owning team based on the `service` label.
- All alerts post a Grafana incident link and the runbook.

### 8.5 Silence Policy

- `silences` are time-bounded (max 4h), require an incident ticket ID, and post a Slack notice to `#sre-silences`.
- Long-term suppressions (e.g., decommissioned service) require a PR removing the alert rule.

---

## 9. Dashboards

### 9.1 Standard Layout

Every service dashboard has five rows:
1. **SLO** — availability, latency, error budget burn, MTTR.
2. **RED** — rate, errors, duration per route.
3. **USE** — CPU, memory, event loop, GC, FD, connections.
4. **Dependencies** — Postgres, Redis, NATS, external APIs.
5. **Saturation & Capacity** — queue depth, concurrency limits, headroom.

### 9.2 Global Dashboards

- **Platform Overview** — one row per service, one panel per SLO.
- **Agent Activity** — task throughput, p50/p95 duration, LLM token spend, tool-invocation error rate.
- **Security Findings Funnel** — discovered → triaged → remediated, by severity.
- **Compliance Posture** — controls passing/failing per framework.
- **Cost & Capacity** — metrics cardinality growth, log volume, trace volume, estimated Prom/Loki/Tempo spend.

### 9.3 Provisioning

All dashboards are JSON provisioned via Grafana's file provisioning (`infra/observability/grafana/provisioning/dashboards/`). Editing in the UI is disabled in prod; PRs only.

---

## 10. Scalability & Cost Plan

### 10.1 Scale Targets (12 months)

| Signal                    | Day 0       | Year 1 target |
|---------------------------|-------------|---------------|
| Backend services          | 6           | 25            |
| Active agents             | 8           | 40            |
| Metrics series            | 5M          | 80M           |
| Log volume (info+warn)    | 20 GB/day   | 500 GB/day    |
| Trace spans               | 5M/day      | 200M/day      |
| Alert rules               | 50          | 400           |

### 10.2 Scaling Strategies

**Prometheus**
- Shard by `service` label using `hashmod` for ≥ 5M series.
- Move to **Mimir** when series count exceeds 10M or regional replication is required. Mimir's ruler and store-gateway support multi-tenant isolation aligned with our tenancy model.
- Enable **agent mode** (Prometheus scrapes from the OTel Collector's `prometheus` exporter for fan-in).

**Loki**
- Run with `boltdb-shipper` or `tsdb` index mode at scale.
- Use `split-by-labels` (tenant, service) for write-path sharding.
- Move cold chunks to a cheaper storage class (S3 IA / GCS Nearline) after 30 days.

**Tempo**
- Enable **ingester streaming** to reduce memory pressure.
- Use `metrics-generator` to emit RED metrics from spans and backfill Prometheus with service-map data.

**OTel Collector**
- **Gateway mode** per node / per pod for tail sampling and enrichment.
- **Agent mode** sidecar for noisy neighbors or high-fanout agents.
- Auto-scale on `otelcol_exporter_queue_size` with HPA.

### 10.3 Capacity Planning Cadence

- **Weekly:** SRE reviews the "Cost & Capacity" dashboard; anomalies paged.
- **Monthly:** Growth-rate forecast; if any signal grows > 2× MoM, trigger a scale plan review.
- **Quarterly:** SLO review; right-size retention; renegotiate object-storage tier.

### 10.4 Cost Guardrails

- **Per-tenant cost attribution** is a first-class requirement. All series, log streams, and trace volumes must carry `tenant_id`. A monthly cost report is delivered to the FinOps team.
- **Cardinality explosions** are caught by a PromQL alert on `prometheus_tsdb_head_series` rate-of-change.
- **Log volume per service** is monitored; top-10 talkers get a weekly report and a request to justify volume.

---

## 11. Security & Compliance Integration

| Concern                     | Mechanism                                                                 |
|-----------------------------|---------------------------------------------------------------------------|
| Telemetry authenticity      | mTLS between OTel Collectors and backends using workload identity.        |
| PII in telemetry            | SDK-level redaction (§5.4) + Collector-level safety net regex pack.       |
| Audit log immutability      | S3 Object Lock (compliance mode) + 7-year retention (§5.7).               |
| Secrets in spans/logs       | OTel Collector `attributes/remove` + Loki drop rules.                     |
| Tenant isolation            | Per-tenant auth on Grafana, Loki multi-tenant, Tempo tenant header.       |
| Compliance evidence         | SLO reports, alert audit trail, and Grafana dashboards exported quarterly to ComplianceOfficer. |

The exact control mappings to CIS v8 and NIST 800-53 are owned by ComplianceOfficer and live in `docs/compliance/cis-nist-mapping.md`. Observability-specific controls are tagged `OBS-*`.

---

## 12. Disaster & Failure Modes

| Failure                              | Detection                                  | Response                                    |
|--------------------------------------|--------------------------------------------|---------------------------------------------|
| Backend service stops exporting      | `up == 0` for 2m → page                   | Restart / investigate via logs              |
| OTel Collector down                  | `otelcol_receiver_accepted_spans == 0` delta | Page SRE; backend buffers to disk for 5m   |
| Prometheus down                      | Alertmanager `Watchdog` deadman alert     | Failover to HA replica                      |
| Loki down                            | Missing logs dashboard panel alert        | Restore from object storage on recovery    |
| Cardinality explosion               | Series count rate-of-change alert         | Identify culprit service, drop or aggregate |
| Time skew                            | `up{job="ntp"} == 0` alert                | Force NTP sync before redeploy              |
| Trace context lost across services   | `trace_id` presence ratio < 99%            | Page service owner; suspect mTLS/bug        |

---

## 13. Rollout Plan

| Phase | Timeline     | Deliverables                                                                       |
|-------|--------------|-------------------------------------------------------------------------------------|
| 0     | Week 1       | OTel SDK in all 6 services, `/metrics` `/livez` `/readyz` `/startz` endpoints live  |
| 1     | Week 2       | Prometheus + Grafana stack deployed; first RED/USE dashboards online                |
| 2     | Week 3       | Loki + log shipping via Fluent Bit; structured logging enforced                     |
| 3     | Week 4       | Tempo + tail-based sampling; trace-to-logs and trace-to-metrics jumps               |
| 4     | Week 5–6     | SLOs declared for all services; burn alerts live; on-call rotation operational      |
| 5     | Week 7–8     | Mimir / long-term store evaluation; cost dashboards; quarterly review process live  |

---

## 14. Open Questions

1. Do we adopt **Grafana Beyla** for eBPF-based auto-instrumentation of services we don't control? (Decision: spike in Sprint 3.)
2. Single-tenant Grafana org vs. multi-tenant? (Default: multi-tenant with row-level security; revisit at 50 tenants.)
3. Synthetic monitoring (Blackbox exporter) coverage — which endpoints? (Owner: SRE; target: top 20 user flows.)

---

## 15. References

- Google SRE Workbook — *Implementing SLOs*, *Alerting on SLOs*
- OpenTelemetry Specification v1.30 — *Semantic Conventions*
- Prometheus Best Practices — *Naming*, *Labels*
- Grafana Loki — *Multi-tenant*, *Storage*
- CIS Controls v8 — *08 Audit Log Management* (mapped in `docs/compliance/cis-nist-mapping.md`)
- NIST SP 800-53 Rev. 5 — *AU family* (mapped in `docs/compliance/cis-nist-mapping.md`)

---

*End of Monitoring, Logging & Metrics Architecture v1.0*
