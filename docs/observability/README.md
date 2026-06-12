# Observability — AI-DevSecOps Command Center

> **Owner:** SREEngineer
> **Status:** Sprint 1 (Foundations) — v1.0

This directory is the **single source of truth** for everything observability: metrics, logs, traces, health, SLOs, and alerting.

## Quick links

| Topic                  | Doc                                                                                  |
|------------------------|--------------------------------------------------------------------------------------|
| Full architecture      | [`monitoring-architecture.md`](./monitoring-architecture.md)                         |
| SLOs & SLIs            | [`slo-sli-definitions.md`](./slo-sli-definitions.md)                                 |
| Alerts & runbooks      | [`alerting-runbooks.md`](./alerting-runbooks.md)                                     |

## Reference implementations

| Component           | File                                                                                  | Purpose                                |
|---------------------|----------------------------------------------------------------------------------------|----------------------------------------|
| OTel bootstrap      | [`../../backend/common/observability/otel.ts`](../../backend/common/observability/otel.ts) | Initialize OTel SDK in any service     |
| Structured logger   | [`../../backend/common/observability/logger.ts`](../../backend/common/observability/logger.ts) | Pino-based logger with redaction       |
| Health check server | [`../../backend/common/observability/health.ts`](../../backend/common/observability/health.ts) | /livez, /readyz, /startz              |

## Tooling stack (production target)

| Pillar   | Backend    | Use                                              |
|----------|------------|---------------------------------------------------|
| Metrics  | Prometheus | Pull-based scraping; two-tier with federation     |
| Logs     | Loki       | Label-indexed, NDJSON ingest, 14d hot            |
| Traces   | Tempo      | Object-store backed, tail-sampled, 14d           |
| Probes   | Blackbox   | Synthetic HTTP checks                            |
| Visual.  | Grafana    | Unified dashboards, alerting                     |
| Routing  | Alertmanager | PagerDuty / GitHub Issues / Slack               |

## SLO at a glance

| Service        | Availability | Latency (p99)            | Notes                                 |
|----------------|--------------|---------------------------|---------------------------------------|
| auth           | 99.9%        | 250 ms (token) / 500 ms (login) | Hard correctness SLO 99.999%      |
| agent          | 99.5%        | 60 s end-to-end           | Excludes LLM provider latency         |
| security       | 99%          | 24h scan freshness         |                                       |
| incident       | 99.9%        | MTTD < 5 min (P1)         |                                       |
| compliance     | 99.9%        | 24h evidence freshness     |                                       |
| integration    | 99.5%        | 1 s p99                   | Webhook delivery 99%                  |

Full SLO catalog and burn-rate alert rules live in [`slo-sli-definitions.md`](./slo-sli-definitions.md) and [`alerting-runbooks.md`](./alerting-runbooks.md).

## Cardinality budget (high level)

| Metric family                    | Budget     |
|----------------------------------|------------|
| `http_server_requests_*` / svc   | 50,000     |
| `agent_task_*` / agent           | 10,000     |
| `*_llm_tokens_total`              | 5,000      |
| Anything else                    | 1,000      |

Enforced by [`../../infra/observability/prometheus/cardinality_lint.py`](../../infra/observability/prometheus/cardinality_lint.py) in CI.

## Where to start

1. Read the [architecture doc](./monitoring-architecture.md) end-to-end — it's the canonical reference.
2. Skim the [SLO catalog](./slo-sli-definitions.md) for the service you own.
3. Bookmark the [runbook](./alerting-runbooks.md) for your service.
4. Adopt the [reference OTel bootstrap](../../backend/common/observability/otel.ts) and [logger](../../backend/common/observability/logger.ts).

## Change process

All changes to this directory are reviewed by SRE on every PR. SLO changes are breaking changes and require sign-off from Product, Security, and SRE.
