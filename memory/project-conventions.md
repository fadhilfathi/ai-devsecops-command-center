---
name: Project Conventions for AI-DevSecOps-Command-Center
description: The locked conventions of the AI-DevSecOps-Command-Center monorepo
type: project
---

# Project Conventions

> These are the conventions the team has locked in as of Sprint 1. If you
> are about to make a change that would break one of these, **stop** and
> raise it with the Lead first.

## Naming

- **Package names**: `@aicc/<service-or-package>`, e.g.
  `@aicc/auth-service`, `@aicc/agent-service`, `@aicc/shared`.
  **Not** `@cc/...`.
- **Service ports**: `auth=3001`, `agent=3002`, `security=3003`,
  `incident=3004`, `compliance=3005`, `integration=3006`.
- **Frontend port**: `5173` (Vite dev server).

## Layout

```
/
├── .github/                 Workflows, CODEOWNERS, dependabot, templates
├── docs/
│   ├── adr/                 ADRs (NNNN-kebab.md, YAML frontmatter, Nygard format)
│   ├── architecture/        System, agents, event-bus, security, auth, GitHub
│   ├── agents/              Agent topology deep-dive
│   ├── compliance/          CIS v8, NIST 800-53, evidence, audits
│   ├── security/            Threat model, hardening, secrets, IR
│   ├── observability/       Monitoring, logging, metrics
│   ├── runbooks/            Operator procedures
│   └── operations/          SLOs, on-call
├── frontend/                AionUi SPA (Vite + React + TS + Tailwind)
├── backend/
│   ├── services/            auth, agent, security, incident, compliance, integration
│   ├── packages/            shared libraries (contracts, events, types, utils)
│   └── common/              cross-cutting modules (observability, …)
├── agents/                  Agent definitions (core, roles, skills)
├── infra/
│   ├── docker/              Dockerfiles
│   ├── kubernetes/          k8s manifests (kustomize overlays)
│   ├── terraform/           IaC
│   └── observability/       prometheus/, otel-collector/, alertmanager/, grafana/, logs/
├── scripts/                 setup/, deploy/, ci/, dev/
├── tests/                   e2e/, integration/, load/
├── memory/                  Team coordination notes (indexed in MEMORY.md)
├── .env.example
├── .gitignore
├── .editorconfig
├── .gitattributes
├── .nvmrc                   Node 20.18.0
├── .dockerignore
├── docker-compose.yml
├── Makefile
├── package.json             Workspace root, scripts
├── pnpm-workspace.yaml
├── tsconfig.base.json       Strict TS
├── LICENSE                  Apache-2.0
├── README.md
├── CHANGELOG.md
├── PROJECT_DESCRIPTION.md
├── CONTRIBUTING.md
├── SECURITY.md
└── CODE_OF_CONDUCT.md
```

## Stack

- **Node.js** 20.18.0 (`.nvmrc`)
- **pnpm** 9.12.0 workspaces
- **TypeScript** 5.5+, strict mode
- **Fastify 4** (not 5)
- **PostgreSQL** 16
- **Redis 7** (Streams)
- **OpenTelemetry**, **Prometheus**, **Grafana**, **Loki**
- **Docker Compose v2** for local dev
- **Kubernetes** + **kustomize** for staging/prod
- **Conventional Commits** required
- **Apache-2.0** for source

## Ownership of folders

| Folder                       | Owner              |
| ---------------------------- | ------------------ |
| `.github/`, root configs, `Makefile`, `docker-compose.yml`, `LICENSE` | **GitOpsManager** |
| `docs/architecture/*` (system, agents, event-bus, security-model) | PlatformArchitect (canonical); GitOpsManager (drafts) |
| `docs/architecture/authentication-and-security-design.md`, `github-integration.md` | SecurityArchitect |
| `docs/adr/0001-0004`         | PlatformArchitect  |
| `docs/adr/0005-0007`         | GitOpsManager      |
| `docs/compliance/`           | ComplianceOfficer  |
| `docs/security/`             | SecurityArchitect  |
| `docs/observability/`        | SREEngineer        |
| `docs/runbooks/`, `docs/operations/` | SREEngineer |
| `docs/agents/`               | PlatformArchitect  |
| `backend/services/*`         | FullstackEngineer  |
| `backend/packages/shared/`   | FullstackEngineer  |
| `backend/common/*`           | SREEngineer / cross-cutting owners |
| `frontend/`                  | UIUXEngineer       |
| `agents/`                    | PlatformArchitect  |
| `infra/`                     | SREEngineer        |
| `memory/`                    | shared (indexed in `MEMORY.md`) |

## Conventions to follow

- **Strict TypeScript** with `noUncheckedIndexedAccess`,
  `noImplicitAny`, `noUnusedLocals`, `noUnusedParameters`,
  `strictNullChecks`.
- **Conventional Commits** for every commit.
- **One PR per change** with the PR template filled out.
- **No secrets in `.env` files in production.** Use a secret manager.
- **Multi-tenant by default.** Every table has a `tenant_id`.
- **Audit log on every state change.** Append-only, HMAC-chained.
- **Agent contracts are typed and versioned.** No untyped LLM calls.
- **OpenSSF Scorecard** is a release gate.

## Anti-patterns to avoid

- Don't create a service without a typed contract and an ADR.
- Don't add a dependency without checking the license and updating
  the SBOM.
- Don't merge a PR that drops test coverage.
- Don't ship a feature without a runbook.
- Don't disable a security control to "fix" something.
