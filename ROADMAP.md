# Roadmap

The AICC platform roadmap evolves sprint by sprint. Each
sprint ships a coherent, demoable capability. The status of
each sprint is reflected in the `CHANGELOG.md` and the
`docs/architecture/sprint-N/` notes.

## Sprint 1 — Repository skeleton, architecture, documentation

Status: **complete** (Sprint 1 release).

- Monorepo layout, full directory tree, all six service
  scaffolds, GitHub workflows, observability drafts.
- Architecture documents: `event-bus`, `agent-topology`,
  `security-model`, `system-architecture`.

## Sprint 2 — Security foundation

Status: **complete** (2026-06-12).

- `vuln-intel` (port 4008) — CVE ingestion, NVD/GHSA/OSV,
  EPSS, KEV, per-feed validation, cross-source consensus,
  LLM exploit scoring, audit log.
- `dependency-intel` (port 4009) — SBOM ingest, dependency
  graph, personalised PageRank on the reversed graph.

## Sprint 3 — Agent runtime

Status: **complete**.

- `agent-service` — dispatcher, contract registry, memory.
- `security-service` — assets, SBOM, vulnerabilities.
- Front-end visualisations (Security Score, Vuln Timeline,
  Risk Heatmap, Dependency Graph, SBOM Viewer).

## Sprint 4 — Kubernetes & Infrastructure Intelligence (current)

Status: **complete** (2026-06-16).

- `kubernetes-service` (port 4006) — read-only K8s
  inventory (clusters, namespaces, workloads, pods,
  services, ingresses, deployments, statefulsets,
  daemonsets, test-connection).
- `k8s-health-service` (port 4007) — health scoring
  (cluster / namespace / workload / pod), issue detection
  (CrashLoopBackOff, ImagePullBackOff, OOMKilled, pending,
  failed, restart storms, node pressure, unschedulable
  workloads), recommendations.
- `runtime-security-service` (port 4008) — 9 rules
  (privileged, hostPath, root, dangerous capabilities,
  weak SecurityContext, ServiceAccount risk, RBAC risk,
  missing limits, unpinned images), per-finding report.
- `inventory-service` (port 4009) — unified asset catalog,
  relationship graph, dependency graph.
- `cost-intelligence-service` (port 4010) — request /
  limit analysis, over-provisioning, under-utilization,
  missing requests / limits, noisy neighbour, cold
  workload, recommendations.
- `topology-service` (port 4011) — Service Map,
  Application Graph, Topology Graph, per-namespace view,
  namespace relationships.
- `reporting-service` (port 4012) — 6 reports × {json,
  md, pdf} (Cluster Health, Infrastructure Risk, Runtime
  Security, Cost Optimization, Topology, Executive
  Summary).
- AionUi infrastructure dashboard (9 new pages under
  `/infrastructure/...`).
- AI incident correlation engine extension for K8s +
  CI/CD + deployment events.

## Sprint 5 — Live Kubernetes + Persistence

Status: **complete** (2026-09-22). See
[`docs/architecture/sprint-5/`](./docs/architecture/sprint-5/).

- ✅ S5-0: build baseline — monorepo installs and builds cleanly,
  CI lint/format/typecheck green.
- ✅ S5-1: vitest test baseline — 198 tests across 13 services +
  `@aicc/shared` + `@aicc/models`, CI test matrix green.
- ✅ S5-2: wire the live `KubernetesProvider` using
  `@kubernetes/client-node`.
- ✅ S5-3: move the cluster registry, incidents, runbooks, and
  chain repository to Postgres (in-memory stays the default;
  correlation buffer stays in-memory — sliding window, not
  a source of truth).
- ✅ S5-4: add Prometheus `/metrics` (HTTP request histogram/counter) to
  every service via `@aicc/observability`'s `registerHttpMetrics`.
- ✅ S5-5: add network-policy inference and Istio / Linkerd
  service-mesh edge discovery to the topology engine.
- ✅ S5-6: containerise all 13 backend services + frontend
  (`backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml`,
  CI Docker build matrix).
- ✅ S5-7: replace the heuristic utilisation estimates in the cost
  engine with real Prometheus queries (kubelet/cAdvisor metrics),
  falling back to the synthetic values when `PROMETHEUS_URL` isn't set.
- ✅ S5-8: upgrade the PDF report formatter to pdfkit — multi-page
  layout, running headers/footers with page numbers, wrapped
  tables, and vector bar charts.

## Sprint 6 — Frontend integration, auth, event bus, compliance automation

Status: **complete** (2026-09-23). See
[`docs/architecture/sprint-6/`](./docs/architecture/sprint-6/).

- ✅ **S6-1**: wire the frontend to the real service APIs instead of
  `src/lib/*.mock.ts`, starting with the infrastructure pages
  (clusters, namespaces, workloads, runtime security, topology,
  cost, health).
- ✅ **S6-2**: auth end-to-end — `auth-service` issues JWTs, every
  backend service verifies them via a shared middleware in
  `@aicc/shared`, and the frontend gets a real login flow (replacing
  the `x-tenant-id`-header development shortcut). A follow-up closed a
  tenant-header spoofing hole left by the first cut. See
  [ADR 0013](./docs/adr/0013-service-to-service-auth.md).
- ✅ **S6-3**: event bus driver beyond in-memory — Redis Streams,
  using the existing compose `redis` container, behind the same
  `EventBus` interface. See
  [ADR 0014](./docs/adr/0014-redis-streams-event-bus.md).
- ✅ **S6-4**: compliance auto-mapping of K8s runtime risks and
  cluster health issues to CIS / NIST controls, with evidence
  attachment, reusing the existing `control-mapper` rules engine. See
  [ADR 0015](./docs/adr/0015-infrastructure-compliance-mapping.md).
  Deferred: continuous compliance scoring per cluster / per tenant,
  control-scoring weights, drift/attestation.
- ✅ **S6-5**: encrypt cluster credentials (`kubernetes-service`'s
  `clusters` table `token`/`ca_bundle` columns) at rest — follow-up
  from [ADR 0010](./docs/adr/0010-postgres-persistence.md). See
  [ADR 0016](./docs/adr/0016-credential-encryption-at-rest.md).

## Sprint 7 — Hardening, security review, OpenSSF Scorecard pass

Status: **complete** (2026-09-24). See
[`docs/architecture/sprint-7/`](./docs/architecture/sprint-7/).

- ✅ **S7-1**: done. Fixed the 45 outstanding `eslint` warnings (mostly
  `@typescript-eslint/no-unused-vars` / `no-explicit-any`) and switched
  CI's `pnpm lint` to `--max-warnings 0` so the count can't silently
  grow back.
- ✅ **S7-2**: dependency / supply-chain pass — Fastify 4→5 across all 13
  services + `@aicc/shared` + `@aicc/observability` (`loggerInstance`,
  `setErrorHandler<FastifyError>`), vitest 2→4 (+ vite 5→7,
  `@vitejs/plugin-react` 4→5), react-router-dom 6→7 in the frontend,
  `pyjwt` 2.13.0 in `vuln-intel`, `pytest` 9 in `dependency-intel`.
  `pnpm audit`: 0 critical / 0 high / 0 moderate / 0 low. Dependabot
  config consolidated to one root npm entry (was 8 overlapping npm
  entries) plus grouped pip entries for the 3 Python agents.
  See [ADR 0017](./docs/adr/0017-fastify-5.md).
- ✅ **S7-3**: done. Fixed the 4 workflows that had been failing on
  every push to `main` (`sbom`, `security`, `scorecard`, `codeql`);
  deleted `security.yml` and `security-issue.yml` (dead GitOps
  automation from the deleted multi-agent era — no producer ever
  existed for their `repository_dispatch` triggers, and the
  `attach-sbom` job in `release.yml` that depended on them). Pinned
  every third-party action across all workflows to a commit SHA with
  a `# vX.Y.Z` comment; Dependabot keeps them current. Least-privilege
  `permissions:` on every workflow/job; `persist-credentials: false`
  on every non-pushing checkout. Rewrote `SECURITY.md` to drop
  fictional teams/SLAs/PGP keys and describe only the automation that
  actually exists. Added `docs/operations/branch-protection.md`
  (manual checklist, not yet applied). Fixed README's hardcoded
  "pending" CI/CodeQL badges to point at the real workflow badges.
- ✅ **S7-4**: done. `registerSecurityPlugins` (`@aicc/shared/http`)
  replaces every service's `cors({ origin: true, credentials: true })`
  / `helmet({ contentSecurityPolicy: false })` block: CORS allow-list
  (opt-in via `CORS_ORIGINS`, off by default — the SPA is same-origin),
  strict `default-src 'none'` CSP, a configurable `bodyLimit` with
  10 MiB overrides on SBOM/vulnerability ingest routes, and a global
  `@fastify/rate-limit` keyed by verified user id (health/metrics
  exempt, tighter limit on auth login/refresh). `trustProxy` is now an
  IP/CIDR allow-list, not `true`. See
  [ADR 0018](./docs/adr/0018-http-hardening.md).
- ✅ **S7-5**: done. `scripts/e2e-smoke.mjs` mints its own HS256 token,
  waits for all 13 services + frontend `/healthz`, hits one
  authenticated route per service, `/readyz` on the Postgres/Redis-
  backed ones, negative-auth (no token, wrong secret), and the nginx
  `/api/*` proxy — the first time the full compose stack has been
  exercised end to end. `.github/workflows/e2e.yml` runs it against a
  freshly built stack on push to `main` and weekly. Moved Prometheus/
  Alertmanager/Grafana/Loki/OTel behind a compose `observability`
  profile (`docker compose --profile observability up`) — not needed
  to smoke the app, so the default `up` (and the CI run) skips them.
  Fixed a real bug this surfaced: cost-intelligence's and topology's
  HTTP-to-kubernetes-service inventory calls only sent `x-tenant-id`,
  no bearer token, so they 401'd once `AUTH_DEV_BYPASS=false` — both
  now mint a short-lived internal service token per call.

## Sprint 8 — Public release readiness, docs, demo data

Status: **not started**.

The version name below was stale — the project is at 0.3.x, not
0.1.0 — retitled to describe what's actually left before a public
release: demo data, the deferred dependency majors, user-facing docs,
and replacing the last mock-only frontend endpoints with real backend
routes.

- **S8-1** (partially done): `AICC_DEMO_SEED=true` seeds security
  (assets/scans/findings), incident (incidents/runbook), compliance
  (controls), and integration (integrations) repositories on startup —
  idempotent, deterministic, tenant-scoped. The Sprint-4 infra
  services (clusters, kubernetes, cost, topology) already serve
  fixture data and were out of scope here. Still open: wiring this
  into the frontend's `VITE_USE_MOCKS=false` path end-to-end and
  covering SBOM.
- **S8-2**: the Dependabot majors deferred from S7-2 — React 19 (+
  `react-dom`, `@types/react`/`@types/react-dom`), Tailwind 4,
  TypeScript 6. Each needs its own migration/breaking-change pass, not
  a blind merge.
  - **S8-2a** (done): React 19, Tailwind 4, recharts 3, lucide-react 1,
    react-window 2; zustand removed (unused).
  - **S8-2b** (done): TypeScript 6, hoisted to the root `devDependencies`
    only; `@types/node` 22 (Node 22 runtime, not the Dependabot-proposed
    25).
- **S8-3** (done): `docs/quick-start.md` — plain markdown in-repo (no paid
  hosting), aimed at someone cloning the repo for the first time rather
  than a contributor reading ADRs. Linked from `README.md` and
  `docs/architecture/README.md`. Found and fixed in the same pass: the
  sidebar's Infrastructure section linked to `/infrastructure/*` routes
  `frontend/src/App.tsx` never registered (404s), and
  `defaultPort()` in `backend/packages/shared/src/http/index.ts` only
  covered 6 of the 13 services and disagreed with the compose/vite-proxy
  port map for the rest.
- **S8-4**: replace the remaining mock-only frontend endpoints with
  real backend routes — `api.vulnerabilities()`, `api.sbom()`,
  `api.securityScore()`, `api.vulnTimeline()`, `api.riskHeatmap()`,
  and `api.graphData()` currently have no matching backend route at
  all (see `frontend/README.md`).
- **S8-5**: port clash — security-service defaults `SBOM_PIPELINE_URL`,
  `VULN_INTEL_URL` and `DEPENDENCY_INTEL_URL` to `localhost:4007-4009`,
  which Sprint 4 assigned to k8s-health, runtime-security and inventory.
  Give the Python agents their own ports and add them to compose.
