---
name: Observability file layout (dev vs prod)
description: How infra/observability/ and docs/observability/ are organized, and which paths docker-compose uses
type: project
---

# Observability file layout (dev vs prod)

> Owned by SREEngineer. Updated 2026-06-12 after Sprint 1 handoff.

## The split

SREEngineer organizes observability into a **dev/prod split**:

### Documentation (`docs/observability/`)
- `docs/observability/README.md` — entry point
- `docs/observability/monitoring-architecture.md` — three pillars, RED/USE,
  SLO framework, scalability, security/compliance integration, rollout
- `docs/observability/slo-sli-definitions.md` — per-service SLO/SLI catalog
- `docs/observability/alerting-runbooks.md` — alert rules + runbooks

### Production configs (`infra/observability/<tool>/<file>`)
- `infra/observability/prometheus/prometheus.yml`
- `infra/observability/prometheus/alert-rules.yml`
- `infra/observability/prometheus/recording-rules.yml`
- `infra/observability/otel-collector/collector-config.yaml`
- `infra/observability/alertmanager/alertmanager.yml`
- `infra/observability/grafana/provisioning/`
- `infra/observability/grafana/dashboards/`

The `prometheus.yml` uses `external_labels: cluster, region, environment`
with `${env:VAR}` placeholders — set the env vars at startup.

### Dev / docker-compose (`docker-compose.yml` mounts)
The docker-compose file (owned by GitOpsManager) mounts the **prod paths**
directly. This is intentional: the dev config and the prod config share
the same file format, and the dev file is just a simpler version of the
prod file. There are **no** dev-only root-level files in
`infra/observability/` — the dev/prod split is in **templating**
(env vars), not in **file location**.

### Open items (Sprint 2 follow-ups)

- **Loki config**: there is no `infra/observability/loki-config.yaml` in
  the repo. The `loki` container in `docker-compose.yml` uses its
  built-in default config. A commented-out mount in docker-compose.yml
  shows where it would go. **Action**: SREEngineer to publish a Loki
  config (or remove the Loki service until we need it).
- **Runbook URL templating**: `alert-rules.yml` references
  `https://runbooks.example.com/observability/...` — this needs to be
  templated to use `RUNBOOK_BASE_URL` from env. **Action**: SRE to
  templatize.
- **OTel collector exporters**: use `${env:LOKI_URL}`, `${env:TEMPO_URL}`,
  `${env:PROM_REMOTE_WRITE_URL}` — these are now in `.env.example`.

### Reference implementations

- `backend/common/observability/` — TypeScript reference implementations
  (otel.ts, logger.ts, health.ts) for FullstackEngineer to migrate the
  services to.
