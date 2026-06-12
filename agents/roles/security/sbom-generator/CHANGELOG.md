# Changelog

All notable changes to the SBOM generator agent are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — Sprint 2 / S2.1

### Added
- Syft-wrapped FastAPI service on **port 4007** that produces SBOMs
  for Docker / OCI images, Git repositories, filesystems, files,
  archives, and registry catalogs.
- Output formats:
  - CycloneDX 1.5 (JSON + XML)
  - SPDX 2.3 (JSON + tag-value)
  - Syft native JSON (passthrough)
- Multiple output formats per request via the `formats` array.
- HTTP endpoints: `/healthz`, `/readyz`, `/metrics`, `/v1/sbom/formats`,
  `/v1/sbom/source-kinds`, `/v1/sbom/generate`, `/v1/sbom/analyze`,
  `/v1/sbom/quick`.
- Bounded concurrency (`asyncio.Semaphore`) and per-request timeout
  (default 600s, 256 MiB output cap).
- Event bus integration:
  - Subscribes to `aionrs.security.sbom.requests`
  - Publishes to `aionrs.security.sbom.results` and
    `aionrs.security.sbom.events`
  - Pluggable bus (NATS / in-memory).
- Prometheus metrics: job counters, syft duration histogram,
  components-per-scan histogram, gauge for active jobs.
- Structured JSON logging to stdout.
- Multi-tenant awareness via `X-Tenant-Id` header (also plumbed into
  SBOM metadata).
- Optional bearer-token auth (`REQUIRE_AUTH=true`).
- Container image based on `python:3.11-slim`, runs as non-root
  `aionrs:1001`, ships Syft `1.6.0`.
- Test suite:
  - `test_sbom_model.py` — internal model + normalizer
  - `test_output.py` — CycloneDX & SPDX serializers
  - `test_request_model.py` — input validation
  - `test_service.py` — HTTP service (with fakes)
  - `test_agent_and_syft.py` — bus + syft CLI builder
  - `test_telemetry.py` — metrics buffer
- Documentation: `README.md`, `docs/openapi.yaml`,
  `docs/ARCHITECTURE.md`, `docs/RUNBOOK.md`, `SECURITY.md`.
- Dev tooling: `Makefile`, `scripts/build.sh`, `scripts/run-local.sh`,
  `scripts/generate.sh`, `examples/requests.sh`,
  `docker-compose.yml`, `.dockerignore`, `.gitignore`, `.env.example`.
