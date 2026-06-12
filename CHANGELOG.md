# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Repository**: <https://github.com/fadhilfathi/ai-devsecops-command-center>

> :construction: **Pre-alpha**: the public API is not stable. The first
> 0.1.0 release will be tagged when the Sprint 1 milestone is complete.

## [Unreleased]

### Added

- **Repository skeleton** (Sprint 1)
  - Monorepo layout with `pnpm` workspaces (`frontend`,
    `backend/services/*`, `backend/packages/*`, `backend/common/*`).
  - Full directory tree: `docs/`, `frontend/`, `backend/`, `agents/`,
    `infra/`, `scripts/`, `tests/`, `.github/`.
  - Root configuration: `package.json`, `pnpm-workspace.yaml`,
    `tsconfig.base.json`, `.editorconfig`, `.gitattributes`,
    `.gitignore`, `.dockerignore`, `.nvmrc`, `.env.example`.
  - Apache-2.0 `LICENSE` and `NOTICE` placeholder.
  - `docker-compose.yml` for the full local stack (Postgres, Redis,
    six services, frontend, Prometheus, Grafana, Loki, OTel collector).
  - `Makefile` with `up` / `down` / `logs` / `test` / `db-*` /
    `release*` / `clean` targets.
  - GitHub workflows: `ci`, `release`, `codeql`, `sbom`, `scorecard`,
    `labeler`.
  - GitHub repo hygiene: `CODEOWNERS`, `dependabot.yml`,
    `PULL_REQUEST_TEMPLATE.md`, issue templates (bug, feature,
    security), `labeler.yml`.
- **Documentation** (Sprint 1)
  - Top-level: this `CHANGELOG.md`, `README.md`, `PROJECT_DESCRIPTION.md`.
  - `CONTRIBUTING.md` with the full dev workflow, coding standards,
    and testing requirements.
  - `SECURITY.md` with the coordinated disclosure process and
    hardening baseline.
  - `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
  - `docs/architecture/`: `README.md`, `system-architecture.md`,
    `agent-topology.md`, `event-bus.md`, `security-model.md`
    (all Sprint 1 drafts; canonical versions coming from
    PlatformArchitect / SecurityArchitect).
  - `docs/agents/README.md`, `docs/compliance/README.md`,
    `docs/security/README.md`, `docs/runbooks/README.md`,
    `docs/operations/README.md`.
  - `docs/adr/`: 0001–0004 by PlatformArchitect (event-bus transport,
    agent comm, event schemas, six-services-one-DB) and 0005–0007 by
    GitOpsManager (record ADRs, monorepo with pnpm, Docker Compose dev).
- **Service scaffolds** (placeholders for Sprint 1 implementation)
  - README for each of the six backend services: `auth`, `agent`,
    `security`, `incident`, `compliance`, `integration`.
  - README for `backend/packages/shared/`.
  - README for `frontend/` describing the eight screens and
    frontend architecture.
  - READMEs for `agents/core/`, `agents/roles/`, `agents/skills/`.
- **Observability config** (root scaffolding; SREEngineer published the
  authoritative `infra/observability/{prometheus,otel-collector,alertmanager,grafana,logs}/`
  tree — see `/docs/observability/`)
  - `infra/observability/README.md` as the entry point.
  - Initial Prometheus, OTel, Loki, Grafana config drafts (SREEngineer
    published the canonical versions).

### Changed

- (none yet — first release)

### Deprecated

- (none yet — first release)

### Removed

- (none yet — first release)

### Fixed

- (none yet — first release)

### Security

- Documented coordinated disclosure process in `SECURITY.md`.
- Documented the security model (RBAC, multi-tenant isolation, audit
  log, agent safety) in `docs/architecture/security-model.md`.
- Pinned Dependabot to weekly updates with group rules per package.

## Sprint 2 — Security foundation (2026-06-12)

### Added

- **`vuln-intel` service** (S2.2, port 4008) — CVE ingestion, normalization, and scoring
  - Source adapters: NVD 2.0, GitHub Security Advisories (GHSA), OSV.dev
  - Enrichment: FIRST.org EPSS (exploit likelihood) + CISA KEV (known exploited)
  - CVSS 3.0/3.1/4.0 vector parser + custom base-score calculator (no external CVSS lib)
  - Unified `CveRecord` Pydantic schema (CVE-5.0-aligned) with multi-source merge
  - SBOM↔CVE matcher (semver-aware range matching, confidence scoring)
  - FastAPI surface: `POST /vuln-intel/ingest`, `GET /vuln-intel/cve/{id}`,
    `POST /vuln-intel/cve/lookup`, `POST /vuln-intel/score`,
    `POST /vuln-intel/match`, `GET /vuln-intel/stats`, `POST /vuln-intel/sync/once`
  - Health & telemetry: `/livez`, `/readyz` (deep source probe), `/metrics`
  - Append-only JSONL store with restart-safe index; Prometheus instrumentation;
    OTel-ready; structlog JSON logs; non-root Docker image; multi-tenant
  - **36 unit + integration tests passing** (`pytest`, ASGI in-process)

- **`vuln-intel` S2.8 hardening** (single commit, 46 new tests)
  - **Per-feed JSON-Schema validators** (`validators.py`): NVD CVE 5.0 (envelope + per-item), GHSA, OSV, EPSS, KEV. Range-checked numeric fields (CVSS 0–10, EPSS 0–1), severity enum whitelist, port of the AJV schemas from § 3.5. Validators run on every record yielded by the source layer; rejections increment `vuln_intel_validation_rejected_total{source,reason}` and are surfaced in the per-feed audit log.
  - **Safe JSON parsing**: hard `max_depth=20` enforcement, `defusedxml.ElementTree` available for upstream XML feeds. No coerce-on-error — invalid records are rejected, never silently dropped.
  - **Cross-source consensus** (`consensus.py`): HIGH/CRITICAL severity requires corroboration by **≥2 of {NVD, GHSA, OSV}**. Single-source HIGH/CRITICAL is tagged `unofficial` for human review; multi-source gets the `corroborated` tag. Decision class carries `reason ∈ {consensus_ok, single_source_high_critical, below_high}` for metrics/audit labelling.
  - **Per-feed audit log** (`audit.py`): append-only JSONL with file-size-based rotation, thread-safe writes. Every ingest run emits one event: `feed, fetched_at, record_count, accepted_count, rejected_count, signature_valid, validator_version, tenant_id, ingest_run_id, rejected_reasons`. Exposed at `GET /vuln-intel/audit`.
  - **Opt-in LLM exploit scoring** (`llm.py`): `VULN_INTEL_LLM_ENABLED` gate; per-tenant and global token budgets with reservation + refund; OpenAI-compatible `/chat/completions` HTTP client; offline `FakeLlmClient` for tests. Strict `LLM_RESPONSE_SCHEMA` (with `additionalProperties: false`); transport / schema / budget-violation errors all fall back to EPSS. Every call emits an `LlmCallAudit` event. Hooked into the `/vuln-intel/score` flow when `use_llm=true` is passed; default is off.
  - **New metrics** (Prometheus):
    - `vuln_feed_last_refresh_timestamp_seconds{source}` (S2.7 lag-SLO gauge)
    - `vuln_intel_validation_rejected_total{source,reason}`
    - `vuln_intel_consensus_unofficial_total`
    - `vuln_intel_llm_calls_total{status}` (ok / schema_violation / budget_exceeded / transport_error / disabled)
    - `vuln_intel_llm_tokens_total{tenant,kind}`
    - `vuln_intel_llm_budget_remaining{tenant}`
  - **New endpoints**: `GET /vuln-intel/audit`, `GET /vuln-intel/llm/status`
  - **New env vars** (all in `config.py`): `VULN_INTEL_INGEST_SCHEDULE_NVD|GHSA|OSV|EPSS|KEV_MINUTES`, `VULN_INTEL_LLM_*` (model, base_url, api_key, timeout_seconds, max_retries, tenant_budget_tokens, global_budget_tokens, cost_per_1k_micros), `VULN_INTEL_AUDIT_LOG_FILENAME`, `VULN_INTEL_AUDIT_LOG_MAX_BYTES`, `VULN_INTEL_CONSENSUS_MIN_SOURCES_HIGH_CRITICAL`, `VULN_INTEL_FEED_SIGNATURE_REQUIRED`, `VULN_INTEL_VALIDATION_MAX_JSON_DEPTH`
  - **Test coverage** (`test_validators.py`, `test_consensus.py`, `test_audit.py`, `test_llm.py`): 46 new tests covering CF-01..CF-07 (feed validation + consensus) and LP-01..LP-09 (LLM scoring). Full suite **82/82 passing**.

- **`dependency-intel` service** (S2.3, port 4009) — dependency graph + risk
  - CycloneDX/SPDX-compatible SBOM ingest (per-component + per-dependency)
  - Graph builder with PURL-keyed nodes, dedupe across SBOMs, workspace merge
  - Pure-Python personalised PageRank on the **reversed** graph for risk
    propagation from vulnerable leaves up to roots
  - Risk formula: `risk_i = alpha * (0.4 * local_i + 0.6 * pr_i) + (1 - alpha) * baseline`
  - Vulnerability cluster detection (CVE-shared-neighbour groups)
  - GraphML / DOT / JSON export for the UI
  - FastAPI surface: `POST /dep-intel/graph/build`, `GET /dep-intel/graph/{id}`,
    `POST /dep-intel/graph/{id}/correlate`, `POST /dep-intel/risk/calculate`,
    `GET /dep-intel/risk/{id}`, `GET /dep-intel/clusters/{id}`,
    `GET /dep-intel/graph/{id}/export`
  - Talks to `vuln-intel` via the documented S2.5 contract
  - **24 unit + integration tests passing**

- **Smoke tests** in `scripts/`:
  - `smoke_vuln_intel.py` — pure-Python CVSS, model, matcher smoke
  - `smoke_e2e_security.py` — in-process end-to-end (ingest → match → risk)
  - `smoke_boot_services.py` — boots both HTTP services in subprocesses and
    verifies `/livez`, `/metrics`, and OpenAPI paths
  - `verify_compile.py` — bytecode-compile gate

### Changed

- Service skeletons from Sprint 1 now have full implementations in Python
  (vuln-intel, dependency-intel) co-located under
  `agents/roles/security/{vuln-intel,dependency-intel}/`.

## Sprint roadmap (planned)

| Sprint | Focus                                                     |
| ------ | --------------------------------------------------------- |
| 1      | Repo, architecture, documentation, service skeletons      |
| 2      | Auth service: users, tenants, JWT, RBAC                   |
| 3      | Agent runtime: dispatcher, memory, contract registry      |
| 4      | Security service: assets, SBOM, vulnerabilities           |
| 5      | Incident service: lifecycle, correlation, playbooks       |
| 6      | Compliance service: control mapping, evidence, attestations |
| 7      | Integration service: GitHub App, webhooks, outbound       |
| 8      | Frontend: Dashboard, Assets, Incidents                    |
| 9      | Frontend: Vulnerabilities, SBOM, Compliance               |
| 10     | End-to-end workflows, observability, SRE playbooks       |
| 11     | Hardening, security review, OpenSSF Scorecard pass        |
| 12     | 0.1.0 release, public docs, demo data                    |

## Security changelog

> **Status:** Auto-managed by
> [`.github/workflows/security.yml`](.github/workflows/security.yml)
> (owner: GitOpsManager). Do not hand-edit — the bot will
> overwrite any changes inside the markers.

This section is a **pointer** to the canonical, auto-generated
security changelog. It is intentionally lightweight here so
humans don't merge in 200 lines of raw CVE noise every release.
The real data lives under [`security/`](security/) and is
updated continuously by CI.

### Where to look

| What                                  | Where                                                                                          |
| ------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Daily vulnerability findings (NDJSON) | [`security/vulns/<YYYY-MM-DD>.json`](security/vulns/) (90-day retention)                        |
| Weekly digest (Markdown)              | [`security/vulns/weekly-<YYYY-Www>.md`](security/vulns/) (kept indefinitely)                   |
| SBOM artifacts                        | [`security/sboms/<sbom_id>/`](security/sboms/) (kept indefinitely; also attached to Releases)   |
| SBOM index                            | [`security/sboms/index.json`](security/sboms/index.json) (NDJSON, one line per SBOM)            |
| Response SLA                          | [`SECURITY.md` → Response targets (SLA)](SECURITY.md#response-targets-sla)                     |
| Coordinated disclosures               | GitHub Security Advisories tab                                                                 |
| Disclosed CVEs (post-disclosure)      | `CHANGELOG.md` "Security" section of the corresponding release entry                            |

### Schema & contract

See [`security/README.md`](security/README.md) for the locked
folder + event-payload contracts. See
[`docs/runbooks/security-automation.md`](docs/runbooks/security-automation.md)
for the operator runbook (triage, override, rollback).

<!-- BEGIN:auto:security-pointer -->
<!-- END:auto:security-pointer -->

## Release history

| Version | Date       | Notes                           |
| ------- | ---------- | ------------------------------- |
| 0.0.0   | 2026-06-12 | Initial repository skeleton     |

<!--
## [0.1.0] - YYYY-MM-DD

### Added
- …

### Changed
- …

### Fixed
- …
-->
