# AI-DevSecOps-Command-Center

> An AI-native, multi-tenant **DevSecOps command center** that unifies
> assets, incidents, vulnerabilities, SBOM, compliance, and integrations
> behind a single, audit-ready interface — and a fleet of cooperating AI
> agents that do the boring parts for you.

**Repository**: <https://github.com/fadhilfathi/ai-devsecops-command-center>

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Status: Pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)](./CHANGELOG.md)
[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](./.github/workflows/ci.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-pending-lightgrey)](./.github/workflows/codeql.yml)
[![Scorecard](https://img.shields.io/ossf-scorecard/?repository=fadhilfathi%2Fai-devsecops-command-center)](https://scorecard.dev/viewer/?uri=github.com/fadhilfathi/ai-devsecops-command-center)

> **Status**: This repository is in **pre-alpha (Sprint 4 of 12)**. The
> architecture is being defined and the skeletons are being built. Do not
> run anything from `main` in production. See [`CHANGELOG.md`](./CHANGELOG.md)
> for the current state.

**Sprint 4 just shipped**: Kubernetes & Infrastructure Intelligence —
clusters, namespaces, workloads, pods, services, ingresses,
deployments, statefulsets, daemonsets, runtime security, cost
optimization, topology, and 6 infrastructure reports. See
[`docs/architecture/sprint-4/`](./docs/architecture/sprint-4/) and
[`CHANGELOG.md`](./CHANGELOG.md).

---

## Table of contents

- [What is it?](#what-is-it)
- [Why does it exist?](#why-does-it-exist)
- [Screens](#screens)
- [Architecture at a glance](#architecture-at-a-glance)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## What is it?

A single pane of glass for the things that security and platform teams
actually do, all the time:

- See every **asset** (repo, image, service, IaC module) and what's in it.
- Triage **vulnerabilities** with deduplication, prior context, and a
  suggested fix.
- Run **incidents** with a structured lifecycle and a playbook-driven
  response.
- Maintain a real **SBOM** (CycloneDX 1.5) per asset, with diffs and
  license auditing.
- Show a **compliance posture** per framework (CIS v8, NIST 800-53) with
  evidence, not screenshots.
- Wire it all into the systems your developers already use (GitHub,
  GitLab, Jira, Slack, PagerDuty).

Behind the scenes, a fleet of **specialized AI agents** does the tedious
work — opening PR comments, drafting postmortems, mapping findings to
controls, correlating incidents — and does it with a typed, auditable
contract.

## Why does it exist?

Most security tools are a **list of findings**. The work of a security
team is the *workflow* around the list: triage, correlation, remediation
tracking, evidence collection, audit answers. We build a system that
**does the workflow**, not a fancier list.

> Read the full product description in
> [`PROJECT_DESCRIPTION.md`](./PROJECT_DESCRIPTION.md).

## Screens

| Screen             | Path               | One-liner                                              |
| ------------------ | ------------------ | ------------------------------------------------------ |
| **Dashboard**      | `/`                | Live posture, open incidents, top risks, recent activity |
| **Assets**         | `/assets`          | Inventory of code, images, services, IaC               |
| **Incidents**      | `/incidents`       | Active and historical incidents, with playbooks        |
| **Vulnerabilities**| `/vulnerabilities` | Findings, dedup, remediation tracking                  |
| **SBOM**           | `/sbom`            | CycloneDX browser, diff, license and provenance        |
| **Compliance**     | `/compliance`      | Posture per framework, evidence, attestations          |
| **Integrations**   | `/integrations`    | GitHub, GitLab, scanners, etc.                         |
| **Settings**       | `/settings`        | Users, roles, tenants, API tokens, audit access        |

### Infrastructure Intelligence (Sprint 4)

| Screen                       | Path                                | One-liner                                      |
| ---------------------------- | ----------------------------------- | ---------------------------------------------- |
| **Infrastructure Overview**  | `/infrastructure`                   | Fleet-wide rollup of clusters, workloads, runtime risk, cost |
| **Cluster Explorer**         | `/infrastructure/clusters`          | Per-cluster nodes + namespaces + health        |
| **Namespace Explorer**       | `/infrastructure/namespaces`        | Cross-cluster namespace rollup                 |
| **Workload Explorer**        | `/infrastructure/workloads`         | Deployment / StatefulSet / DaemonSet list      |
| **Runtime Security**         | `/infrastructure/runtime-security`  | Privileged, hostPath, root, capabilities, ...  |
| **Topology Viewer**          | `/infrastructure/topology`          | Application / Service Map / Topology Graph     |
| **Cost Intelligence**        | `/infrastructure/cost`              | Resource waste, over-provisioning, savings     |
| **Infrastructure Health**    | `/infrastructure/health`            | Health rollup + issues + recommendations       |
| **Infrastructure Incidents** | `/infrastructure/incidents`         | Incidents correlated to K8s / runtime / cost   |

## Architecture at a glance

```
                       ┌─────────────────────────────┐
                       │        AionUi (SPA)         │
                       └──────────────┬──────────────┘
                                      │ HTTPS / WSS
                                      ▼
                ┌──────────────────────────────────────────┐
                │              API Gateway                  │
                └──────────────┬───────────────────────────┘
                               │
   ┌─────────┬─────────┬───────┼───────┬─────────┬─────────┐
   ▼         ▼         ▼       ▼       ▼         ▼         ▼
  Auth     Agent   Security Incident Compliance  Integration
  (3001)   (3002)   (3003)   (3004)   (3005)      (3006)
   │         │         │       │       │           │
   └─────────┴─────────┴───┬───┴───────┴───────────┘
                           │  Event bus (Redis Streams / NATS)
                           │
                  ┌────────┴─────────┐
                  ▼                  ▼
              Postgres             Redis
              (primary)         (cache, bus)
```

> Full architecture: [`docs/architecture/system-architecture.md`](./docs/architecture/system-architecture.md).
> Architecture decisions (ADRs): [`docs/adr/`](./docs/adr/).
> Agent design: [`docs/architecture/agent-topology.md`](./docs/architecture/agent-topology.md).

## Repository layout

```
.
├── .github/              GitHub workflows, issue templates, CODEOWNERS
├── docs/                 All documentation (architecture, agents, compliance, …)
│   ├── adr/              Architecture Decision Records
│   ├── architecture/     System design
│   ├── agents/           Agent topology deep-dive
│   ├── compliance/       Control mappings & evidence
│   ├── security/         Threat model, hardening
│   ├── runbooks/         Operator procedures
│   └── operations/       SLOs, on-call, dashboards
├── frontend/             AionUi SPA (Vite + React + TypeScript)
├── backend/              Six Fastify services in TypeScript
│   ├── services/
│   │   ├── auth/         Port 3001
│   │   ├── agent/        Port 3002
│   │   ├── security/     Port 3003
│   │   ├── incident/     Port 3004
│   │   ├── compliance/   Port 3005
│   │   └── integration/  Port 3006
│   ├── packages/         # Shared libraries (contracts, events, types, utils)
│   └── common/           # Cross-cutting modules (observability, etc.)
├── agents/               Agent definitions
│   ├── core/             Framework-agnostic agent core
│   ├── roles/            security, incident, compliance, integration
│   └── skills/           Reusable skills
├── infra/                Kubernetes, Terraform, observability
├── scripts/              Setup, deploy, CI, dev helpers
├── tests/                e2e, integration, load
├── .env.example          Environment variables template
├── .gitignore
├── .editorconfig
├── .nvmrc                Pinned Node.js version
├── docker-compose.yml    Local stack
├── Makefile              Common dev / CI commands
├── package.json          Workspace root
├── pnpm-workspace.yaml   pnpm workspaces
├── tsconfig.base.json    Shared TypeScript config
├── LICENSE               Apache-2.0
├── README.md             (you are here)
├── CHANGELOG.md
├── PROJECT_DESCRIPTION.md
├── CONTRIBUTING.md
├── SECURITY.md
└── CODE_OF_CONDUCT.md
```

## Quick start

> Prereqs: **Node.js** `>= 20.18.0`, **pnpm** `>= 9`, **Docker** + **Docker
> Compose v2**. See [`.nvmrc`](./.nvmrc).

```bash
# 1. Clone
git clone https://github.com/fadhilfathi/ai-devsecops-command-center.git
cd ai-devsecops-command-center

# 2. Use the pinned Node version
nvm use    # or: nvm install

# 3. Install
pnpm install

# 4. Configure
cp .env.example .env
# (edit .env — see .env.example for what to set)

# 5. Bring up the full local stack
make up

# 6. Open
# - AionUi (frontend):    http://localhost:5173
# - Grafana:              http://localhost:3001  (admin / admin)
# - Prometheus:           http://localhost:9090
```

### Common commands

| Command              | What it does                                |
| -------------------- | ------------------------------------------- |
| `make up`            | Bring the local stack up                    |
| `make down`          | Tear the local stack down                   |
| `make logs`          | Tail logs                                  |
| `make lint`          | Lint everything                             |
| `make typecheck`     | Type-check everything                       |
| `make test`          | Run unit tests                              |
| `make test-e2e`      | Run e2e tests                               |
| `make db-migrate`    | Run database migrations                     |
| `make db-shell`      | Open a psql shell                           |
| `make release-dry`   | Dry-run a release                           |
| `make help`          | List all targets                            |

## Documentation

Start here:

- **[`PROJECT_DESCRIPTION.md`](./PROJECT_DESCRIPTION.md)** — the full
  product description, personas, use cases, and roadmap.
- **[`docs/architecture/`](./docs/architecture/)** — system, agents,
  event bus, security model (canonical auth: `authentication-and-security-design.md`,
  canonical GitHub integration: `github-integration.md`).
- **[`docs/adr/`](./docs/adr/)** — why we made the choices we made.
- **[`docs/compliance/`](./docs/compliance/)** — control mapping.
- **[`docs/security/`](./docs/security/)** — threat model, hardening.
- **[`docs/observability/`](./docs/observability/)** — monitoring, logging, metrics.
- **[`docs/runbooks/`](./docs/runbooks/)** — operator procedures.
- **[`docs/operations/`](./docs/operations/)** — SLOs, on-call.

## Contributing

We welcome contributions. Please read
[`CONTRIBUTING.md`](./CONTRIBUTING.md) and our
[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) first.

- **Issues**: bug reports and feature requests.
- **Discussions**: questions, RFCs, "how do I…".
- **PRs**: see the [PR template](./.github/PULL_REQUEST_TEMPLATE.md) and
  the [CONTRIBUTING guide](./CONTRIBUTING.md#development-workflow).

## Security

Please **do not** file public issues for security vulnerabilities. See
[`SECURITY.md`](./SECURITY.md) for the coordinated disclosure process.

## License

[Apache License 2.0](./LICENSE). Copyright 2026 MiniMax / AionRs.

## Acknowledgements

This project is built on the shoulders of giants. See
[`docs/architecture/`](./docs/architecture/) for the ADRs that drove our
framework and library choices.
