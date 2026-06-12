# Project Description

> The full product description of the **AI-DevSecOps Command Center**.
> Read this for the *what* and the *why*; read
> [`README.md`](./README.md) for the *how* (in 30 seconds) and
> [`docs/architecture/`](./docs/architecture/) for the deep design.

## 1. One-paragraph pitch

The AI-DevSecOps Command Center is a single, multi-tenant web platform
that gives security and platform teams a **live, audit-ready view** of
their assets, vulnerabilities, incidents, SBOM, and compliance posture —
and a fleet of **typed AI agents** that do the workflow around those
things (PR comments, postmortem drafts, control mapping, evidence
collection) so humans can focus on the decisions only humans can make.

## 2. Who it's for

### Primary personas

- **Security engineer** ("Sarah"). Triages 50–500 findings per week
  across many repos. Wants dedup, prior context, and a clear next
  action. Hates busywork.
- **Platform engineer** ("Pat"). Owns the CI/CD and the runtime. Wants
  a single place to see "what's deployed where, with what risks, and
  does it meet the controls".
- **Compliance lead** ("Casey"). Answers audit questions. Wants
  evidence on demand, not screenshots, and a signed chain back to the
  source events.
- **Engineering manager** ("Morgan"). Reports up the chain. Wants
  posture trends, MTTR, and the few things that need attention this
  week.

### Non-personas (explicit non-goals)

- **End-user / consumer of a product** is *not* a user. The Command
  Center is for the people who build and protect the product.
- **CISO of a Fortune 500 looking for a SIEM replacement** is *not* a
  target. We integrate with SIEMs; we are not one.

## 3. What problems it solves

| Pain                                                | What we do                                     |
| --------------------------------------------------- | ---------------------------------------------- |
| Too many findings, no dedup, no context            | Correlate, dedup, surface prior remediation    |
| Vulnerabilities live in PRs, in trackers, in scanners, in inboxes | One inbox-of-record with live updates |
| "Are we compliant?" is a quarterly fire drill       | Continuous posture with signed evidence        |
| Postmortems are written days after the fact         | Drafted from the incident timeline as it runs  |
| Agents are toys / shadow IT                        | Typed, auditable, policy-enforced, scoped      |
| Audit answers take weeks                            | One API call: produce a signed attestation     |
| Onboarding a new repo is a copy-paste of YAML       | Connect the GitHub App once; the platform does the rest |

## 4. The user experience

The product is a single page application with **eight surfaces**:

1. **Dashboard** — live posture, open incidents, top risks, recent
   activity, agent runs.
2. **Assets** — inventory of repos, images, services, IaC modules.
   Filter, group, tag, drill in.
3. **Incidents** — the active incident queue, the timeline of every
   incident (open or closed), and a structured workflow for the
   response.
4. **Vulnerabilities** — the finding inbox. Deduped, correlated to
   assets, with prior remediation, suggested fix, and a "why we
   ranked it this way" explanation.
5. **SBOM** — the CycloneDX browser. Per-asset SBOM, diff between
   versions, license and provenance view.
6. **Compliance** — posture per framework (CIS v8, NIST 800-53),
   per-control evidence, and a button that generates a signed
   attestation artifact.
7. **Integrations** — connect GitHub, GitLab, scanners (Snyk, Trivy,
   Grype, …), ticketing (Jira, Linear), chat (Slack, Teams), paging
   (PagerDuty, Opsgenie).
8. **Settings** — users, roles, tenants, API tokens, audit log access.

Every surface has **live updates** over WebSocket: when an agent
opens an incident or attaches evidence, the UI updates without a
refresh.

## 5. The AI agent fleet

The platform is not a chat with a single LLM. It is a fleet of
**specialized, typed agents** that collaborate over an event bus:

- **Security agents**: SBOM generator, vulnerability scanner, secrets
  detector, license auditor, container scanner.
- **Incident agents**: correlator, triage assistant, playbook runner,
  postmortem drafter.
- **Compliance agents**: control mapper, evidence collector,
  attestation builder.
- **Integration agents**: PR commenter, ticket creator, notifier.

Each agent is a **typed contract** (input schema, output schema,
events consumed, events produced, blast radius, model tier, max
tokens, timeout, tool allowlist) and a deterministic runtime. The
runtime enforces every part of the contract: a misbehaving agent
cannot exceed its blast radius, call an unauthorized tool, blow
its token budget, or hide its decision from the audit log.

A typical "vulnerability in a PR" flow:

1. GitHub → `integration` (webhook) → `integration.github.pr.opened.v1`
2. `agent` dispatches the **SBOM agent** and the **vuln scanner**
3. `security.sbom.generated.v1`, `security.vulnerability.detected.v1`
4. `incident` correlates against KEV and prior context →
   `incident.incident.opened.v1`
5. `compliance` maps the finding to CIS/NIST →
   `compliance.evidence.attached.v1`
6. The integration agent posts a PR comment, opens a Jira ticket,
   pings Slack — all from the same event.

## 6. Architecture, in one breath

- **Six backend services** (`auth`, `agent`, `security`, `incident`,
  `compliance`, `integration`) in **Node.js + TypeScript + Fastify**.
- **A single SPA** (AionUi) — Vite + React + TypeScript — behind an
  **API Gateway** that does auth, rate-limit, and trace-id
  injection.
- **Event bus**: Redis Streams by default, NATS JetStream as a
  drop-in when we need more.
- **Datastores**: PostgreSQL (system of record, per-service schema),
  Redis (cache + bus), S3-compatible object store (evidence, SBOM).
- **Observability**: OpenTelemetry → Tempo, Prometheus, Loki,
  Grafana.

Full architecture: [`docs/architecture/system-architecture.md`](./docs/architecture/system-architecture.md).
Architecture decisions: [`docs/adr/`](./docs/adr/).

## 7. Security and compliance posture

- **Multi-tenant by design** with hard isolation at the data layer
  (per-tenant row filters, per-service Postgres roles, tenant-scoped
  object-store prefixes, tenant-scoped cache keys).
- **RBAC** with scope-based actions and attribute constraints
  (tenant, environment, asset tag).
- **OIDC / SSO** primary; local username/password only as a
  break-glass fallback.
- **mTLS** for service-to-service traffic in staging and prod.
- **Webhook verification** by HMAC of the raw body, with replay
  protection.
- **Audit log** is append-only, HMAC-chained, and replicated off-host.
  Retention default: 365 days.
- **SBOM** generated on every release; tracked in a vulnerability
  scanner; signed.
- **Agent safety**: declared blast radius, tool allowlist, token
  budget, prompt-injection detection, full decision record per run.

Threat model: [`docs/security/threat-model.md`](./docs/security/threat-model.md).
Disclosure policy: [`SECURITY.md`](./SECURITY.md).
Control mapping: [`docs/compliance/`](./docs/compliance/).

## 8. Deployment and operations

- **Local dev**: `make up` brings up the full stack in Docker Compose
  in under 10 minutes.
- **Staging / prod**: Kubernetes, with kustomize overlays per
  environment. Manifests in `infra/kubernetes/`.
- **PostgreSQL**: managed (RDS / Cloud SQL / Crunchy) or in-cluster.
- **Redis**: managed (ElastiCache / Memorystore) or in-cluster with HA.
- **Object store**: managed (S3 / GCS) or MinIO.
- **Observability stack**: OTel collector, Prometheus, Grafana, Loki.
- **Release process**: `standard-version` from `main`; cut a release
  with the `release` workflow.

SLOs and on-call: [`docs/operations/`](./docs/operations/).
Runbooks: [`docs/runbooks/`](./docs/runbooks/).

## 9. Roadmap

See [`CHANGELOG.md`](./CHANGELOG.md#sprint-roadmap-planned) for the
sprint-by-sprint plan. Headline milestones:

- **0.1.0** (Sprint 12) — end-to-end demo, public docs.
- **0.5.0** — multi-tenant GA, audit-ready attestations.
- **1.0.0** — SOC 2 Type II evidence flow, ISO 27001 mapping, on-prem
  install story.

## 10. Glossary

- **Agent** — a typed unit of work. Has a contract (input, output,
  events consumed, events produced, blast radius, model tier). Runs
  on the `agent` service.
- **Asset** — anything we monitor: a repo, a container image, a
  running service, an IaC module.
- **Control** — a row in a compliance framework (e.g. CIS 5.4 —
  "Restrict administrator privileges").
- **Evidence** — a signed record that a control was satisfied at a
  point in time, linked back to the source event(s).
- **Attestation** — a signed, hash-chained artifact that an auditor
  can verify offline.
- **Blast radius** — what an agent is *allowed* to do (read-only,
  write findings, open incidents, close incidents, …).
- **Playbook** — a structured, declarative response flow for an
  incident class. May invoke tools, agents, or human approvals.

---

> This is a living document. Edit it when the product changes.
> Source of truth for *why* we are building it lives in the
> [`docs/adr/`](./docs/adr/).
