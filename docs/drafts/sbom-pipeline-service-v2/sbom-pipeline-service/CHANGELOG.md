# Changelog

All notable changes to the SBOM pipeline service are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — Sprint 2 / S2.1

### Added
- Syft-wrapped FastAPI service on **port 4007** that generates,
  normalizes, analyzes, and stores SBOMs.
- Source prefix syntax (Lead-locked): `docker:` | `git:` | `fs:` |
  `lockfile:`. All four prefixes handled in a single string field.
- Output formats:
  - CycloneDX 1.5 (JSON + XML)
  - SPDX 2.3 (JSON + tag-value)
  - Syft native JSON (passthrough)
- HTTP endpoints (Lead-locked contract):
  - `POST /sbom/generate`
  - `POST /sbom/analyze`
  - `GET  /sbom/{id}?format=…`
  - `GET  /sbom?page=&page_size=`
  - `DELETE /sbom/{id}`
  - `GET /healthz`, `GET /readyz`, `GET /metrics`
- Persistence:
  - SQLite metadata DB (dev) — `sboms` table with all required
    columns (`id`, `source`, `format`, `data_json`, `created_at`,
    `sha256`, `size_bytes`, …).
  - Filesystem object store (dev) at `backend/data/sbom-store/`.
  - SQLAlchemy 2.x async + aiosqlite; switch to Postgres in prod
    by setting `SBOM_DB_URL=postgresql+asyncpg://…`.
  - Optional S3 object store via `SBOM_OBJECT_STORE_URL=s3://…`.
- Analyzer (transitive depth, ecosystems, licenses, total size).
  - Longest-path DFS with cycle guard.
  - Ecosystem bucket from purl prefix.
  - License breakdown incl. ``unknown`` bucket for undeclared.
  - `size_bucket` helper for the S2.7 metric label.
- Event bus integration (Lead-locked + GitOpsManager contract):
  - Subscribes to `security.sbom.requested.v1`.
  - Publishes to `security.sbom.{generated,failed,analyzed,stored}.v1`.
  - Pluggable bus: `NATSClient` (default) or `InMemoryBus`.
  - Bus failures are best-effort and never break a successful scan.
- Click CLI: ``python -m sbom_pipeline generate|analyze|list|get|delete|serve``.
  - `generate` supports `--offline` mode (no live service required).
- OTel + Prometheus instrumentation with the SRE-locked metric set:
  - `devsecops_sbom_generation_duration_seconds` (labels:
    `source_type`, `result`, `format`, `ecosystem`).
  - `devsecops_sbom_jobs_total` (labels: `result`, `source_type`).
  - `devsecops_sbom_component_count` (labels: `source_type`).
  - `devsecops_active_scans` (labels: `scanner_type`).
  - `devsecops_queue_depth` (labels: `queue_name`).
  - `devsecops_eventbus_lag_seconds` (labels: `stream`,
    `consumer_group`, `subject`).
  - `devsecops_eventbus_publish_errors_total`.
- Optional bearer-token auth (`SBOM_REQUIRE_AUTH=true`).
- Container image based on `python:3.11-slim`, runs as non-root
  `aionrs:1001`, ships Syft `1.6.0` (pinned by build arg), tini as
  PID 1, healthcheck against `/healthz`.
- Test suite:
  - `test_syft_wrapper.py` — command builder, ecosystem extraction.
  - `test_parsers.py` — CycloneDX + SPDX serializers, round-trip.
  - `test_analyzer.py` — stats, cycle guard, license breakdown.
  - `test_api.py` — full HTTP service (with fakes, no live Syft).
- Documentation: `README.md` (full API reference + handoff notes).
- Dev tooling: `.env.example`, `.dockerignore`, `.gitignore`.

### Notes
- Earlier (v1) work at `agents/roles/security/sbom-generator/` is
  kept on disk as a reference design. The canonical implementation
  for S2.1 is this service at `backend/services/sbom-pipeline-service/`.
