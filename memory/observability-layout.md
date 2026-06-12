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

All Sprint 1 follow-up items resolved as of 2026-06-12:

- ✅ **Loki config** — `infra/observability/loki-config.yaml` published.
- ✅ **Runbook URL templating** — alert rules and SLO burn template use
  `{{ $labels.runbook_base_url }}` / `{{ $labels.dashboard_base_url }}`
  with the labels driven by `external_labels` and the env vars
  `RUNBOOK_BASE_URL` / `DASHBOARD_BASE_URL`.
- ✅ **Stale path in `memory/monitoring-architecture.md`** — fixed by
  SREEngineer; now points to the subfolder.
- ✅ **Dev/prod split** — resolved as "same files, different env vars".
  No separate dev root files. Documented in `infra/observability/README.md`.

### Reference implementations

- `backend/common/observability/` — TypeScript reference implementations
  (otel.ts, logger.ts, health.ts) for FullstackEngineer to migrate the
  services to.

## Closed items (historical)

All Sprint 1 follow-ups resolved as of 2026-06-12:

- ✅ **Loki config** — SREEngineer published
  `infra/observability/loki-config.yaml`.
- ✅ **Runbook URL templating** — SREEngineer templatized in
  `alert-rules.yml` and `slo-burn.yml.j2` with
  `{{ $labels.runbook_base_url }}` / `{{ $labels.dashboard_base_url }}`
  driven by `external_labels` + `RUNBOOK_BASE_URL` / `DASHBOARD_BASE_URL`.
- ✅ **Stale path in `memory/monitoring-architecture.md`** — SRE fixed
  line 47; now points to `infra/observability/alertmanager/alertmanager.yml`.
- ✅ **Dev/prod split** — resolved as "same files, different env vars".
  No separate dev root files. Documented in
  `infra/observability/README.md`.
