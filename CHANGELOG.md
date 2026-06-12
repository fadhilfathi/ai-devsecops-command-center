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
