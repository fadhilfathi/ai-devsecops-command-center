# Observability configuration

> Prometheus, Grafana, Loki, and the OpenTelemetry collector configs.
> Mounted by `docker-compose.yml` in the repo root.
>
> **Owner**: SREEngineer (canonical configs). GitOpsManager owns this
> README as the entry point and the docker-compose wiring.

```
infra/observability/
├── README.md                            (this file)
├── loki-config.yaml                     (Loki local config)
├── prometheus/
│   ├── prometheus.yml                   (scrape + alerting config)
│   ├── alert-rules.yml                  (PromQL alert rules)
│   ├── recording-rules.yml              (precomputed series)
│   ├── cardinality_lint.py              (CI lint for label cardinality)
│   └── templates/
│       └── slo-burn.yml.j2              (Jinja template for SLO burn)
├── otel-collector/
│   └── collector-config.yaml            (OTLP receivers + exporters)
├── alertmanager/
│   └── alertmanager.yml                 (alert routing + silences)
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/                 (Prometheus, Loki datasources)
│   │   └── dashboards/                  (dashboard providers)
│   └── dashboards/
│       └── service-overview.json        (starter dashboard)
└── logs/
    └── log-schema.json                  (canonical log event schema)
```

## Dev vs prod

The same files work for both **dev** (docker-compose) and **prod**
(k8s/Helm). The split is in **env vars at startup**, not in **file
location**:

| Variable                  | Dev (docker-compose)        | Prod (k8s)                 |
| ------------------------- | --------------------------- | -------------------------- |
| `RUNBOOK_BASE_URL`        | `https://runbooks.example.com/observability` | real host |
| `DASHBOARD_BASE_URL`      | `http://localhost:3001`     | real Grafana host          |
| `LOKI_URL`                | `http://loki:3100`          | real Loki endpoint         |
| `TEMPO_URL`               | `http://tempo:4317`         | real Tempo endpoint        |
| `PROM_REMOTE_WRITE_URL`   | `http://prometheus:9090/api/v1/write` | real remote write |
| `ALERTMANAGER_URL`        | `http://alertmanager:9093`  | real Alertmanager endpoint |

`RUNBOOK_BASE_URL` and `DASHBOARD_BASE_URL` are exposed as Prometheus
`external_labels` so the alert rules can reference them via
`{{ $labels.runbook_base_url }}/<alertname>` and
`{{ $labels.dashboard_base_url }}/<dashboard-uid>`.

## Quick reference

- **Prometheus** scrapes every service's `/metrics` endpoint and the
  event bus's internal metrics. UI on `:9090`.
- **Grafana** is pre-provisioned with datasources (Prometheus, Loki) and
  a starter dashboard set. UI on `:3001` (default `admin` / `admin`).
- **Loki** aggregates logs from every service. UI is Grafana → Explore.
- **OpenTelemetry collector** receives OTLP (gRPC `:4317`, HTTP `:4318`)
  and exports traces, metrics, and logs to the configured backends.
- **Alertmanager** routes alerts based on `alertmanager.yml` rules.
  UI on `:9093`.

## Conventions

- All services expose a `GET /metrics` endpoint (Prometheus text format).
- All services emit **structured JSON logs** to stdout in production; the
  collector ships them to Loki.
- Every request gets a **trace id** (`traceparent`); the same id appears
  in logs and metrics.
- Alert rules include a `runbook` annotation (mandatory; the linter
  rejects alerts without one) and a `dashboard` annotation (recommended).

## See also

- [`/docs/observability/README.md`](../../docs/observability/README.md) —
  the architecture.
- [`/docs/observability/monitoring-architecture.md`](../../docs/observability/monitoring-architecture.md)
- [`/docs/observability/slo-sli-definitions.md`](../../docs/observability/slo-sli-definitions.md)
- [`/docs/observability/alerting-runbooks.md`](../../docs/observability/alerting-runbooks.md)
- [`/docs/operations/`](../../docs/operations/) — SLOs, alerting, on-call.
