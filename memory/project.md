---
name: AI DevSecOps Command Center — Project
description: Project context, team, tech stack, and how to collaborate
type: project
---

# AI DevSecOps Command Center

Multi-agent AI DevSecOps platform powered by AionUi.

**Workspace:** `C:\Users\fadhi\OneDrive\Documents\AI-DevSecOps-Command-Center`
**Model policy:** TokenRouter / MiniMax-M3 (via aionrs backend)
**Mode:** YOLO — autonomous execution enabled

## Team (7 agents, all spawned 2026-06-12)

| Agent | Slot | Sprint 1 output |
|---|---|---|
| SecurityArchitect | `019ebae2-9de4-7223-9920-60866bc88d45` | Auth design, GitHub App design |
| PlatformArchitect | `019ebae2-9df9-7db0-a45b-c36d235b811e` | System architecture, agent topology, event bus |
| SREEngineer | `019ebae2-9e02-7e01-9b2b-451eb0d20f59` | Observability architecture, SLOs, runbooks |
| ComplianceOfficer | `019ebae2-9e0c-7981-ba99-225c9c32226d` | CIS Controls v8 mapping |
| UIUXEngineer | `019ebae2-9e15-75b3-9d62-0aca5b05788e` | 8 AionUi screens, design system |
| FullstackEngineer | `019ebae2-9e1c-7273-a8ce-e74cc95e5b0a` | 6 Fastify services, monorepo |
| GitOpsManager | `019ebae2-9e25-7970-952c-4236216ff0d5` | Repo, governance, CI, ADRs |

## Tech Stack (locked by PlatformArchitect + SecurityArchitect)

- **Frontend:** React 18 + Vite 5 + TypeScript (strict) + Tailwind 3 + TanStack Query + Zustand + Axios + Recharts + Lucide
- **Backend:** Node.js 20 + TypeScript + Fastify + npm workspaces (Turborepo-ready)
- **DB:** PostgreSQL 15+ (schema-per-service, RLS)
- **Cache/Event Bus:** Redis 7 with Streams (NATS JetStream migration path)
- **Object store:** S3-compatible (evidence, SBOMs)
- **Agents:** Python 3.11 runtime (planned Sprint 2)
- **AuthN/Z:** JWT RS256, RBAC + per-tenant scope
- **Observability:** Prometheus + Loki + OpenTelemetry + Grafana
- **CI/CD:** GitHub Actions (CI, CodeQL, SBOM, Scorecard, Release, Labeler) + Dependabot
- **Compliance:** CIS v8 + NIST 800-53 r5 + SOC 2 TSC

## Sprint 1 Outcome

**2 commits · 237 files · 16,990 insertions**
- `269aa9e` — initial skeleton (232 files, 16,889 insertions)
- `19235ef` — follow-up ADRs + memory index (6 files, 101 insertions)

10/10 success criteria met. See [sprint-1-status.md](./sprint-1-status.md).

## Coordination Protocol (discovered during Sprint 1)

- **Spawned agents share a workspace with each other** but the Leader's filesystem is isolated from theirs.
- Therefore: spawned agents must call Write/Bash directly, and the Leader must trust the filesystem artifacts they produce (verified via Glob/find) — do NOT require them to dump content inline.
- The earlier "STATUS CHECK" message that asked agents to return content inline was unnecessary and caused confusion.
- The team task board is the source of truth for ownership; update statuses there on completion.

## Conventions

- ADRs: `docs/adr/NNNN-kebab-case.md` (MADR-lite)
- Topics: `domain.entity.action`
- Envelope: CloudEvents 1.0
- Ports: 4001-4006 (Sprint 1) — Sprint 2 may move to 3001-3006 per the original Leader spec
- Logging: pino structured JSON
- Tracing: OpenTelemetry, W3C trace context

## Open Questions for Human

- Sprint 2 kickoff signal needed before resuming agent work
- Cloud / region target (currently us-east-1 is used in mock data)
- IdP choice (OIDC/PKCE)
- Whether the AionUi brand needs a logo / wordmark
- Light vs dark theme (currently dark-only)
