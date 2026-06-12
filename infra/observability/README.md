# Observability configuration

> Prometheus, Grafana, Loki, and the OpenTelemetry collector configs.
> Loaded by `docker-compose.yml` in the repo root.

```
infra/observability/
├── README.md
├── prometheus.yml
├── otel-collector.yaml
├── loki-config.yaml
├── grafana/
│   └── provisioning/
│       ├── datasources/
│       └── dashboards/
└── alertmanager.yml
```

## Quick reference

- **Prometheus** scrapes every service's `/metrics` endpoint and the
  event bus's internal metrics. UI on `:9090`.
- **Grafana** is pre-provisioned with datasources (Prometheus, Loki) and
  a starter dashboard set. UI on `:3001` (default `admin` / `admin`).
- **Loki** aggregates logs from every service. UI is Grafana → Explore.
- **OpenTelemetry collector** receives OTLP (gRPC `:4317`, HTTP `:4318`)
  and exports traces to the tracing backend (Tempo or a vendor).

## Conventions

- All services expose a `GET /metrics` endpoint (Prometheus text format).
- All services emit **structured JSON logs** to stdout in production; the
  collector ships them to Loki.
- Every request gets a **trace id** (`traceparent`); the same id appears
  in logs and metrics.

See [`/docs/operations/`](../../docs/operations/) for SLOs, alerting, and
on-call.
