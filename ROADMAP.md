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

Status: **planned**.

- ✅ **S6-1**: wire the frontend to the real service APIs instead of
  `src/lib/*.mock.ts`, starting with the infrastructure pages
  (clusters, namespaces, workloads, runtime security, topology,
  cost, health).
- ✅ **S6-2**: auth end-to-end — `auth-service` issues JWTs, every
  backend service verifies them via a shared middleware in
  `@aicc/shared`, and the frontend gets a real login flow (replacing
  the `x-tenant-id`-header development shortcut). See
  [ADR 0013](./docs/adr/0013-service-to-service-auth.md).
- ✅ **S6-3**: event bus driver beyond in-memory — Redis Streams,
  using the existing compose `redis` container, behind the same
  `EventBus` interface. See
  [ADR 0014](./docs/adr/0014-redis-streams-event-bus.md).
- **S6-4**: compliance auto-mapping of K8s runtime risks to CIS /
  NIST controls, with evidence attachment from inventory, health,
  and runtime services, and continuous compliance scoring per
  cluster / per tenant.
- **S6-5**: encrypt cluster credentials (`kubernetes-service`'s
  `clusters` table `token`/`ca_bundle` columns) at rest — follow-up
  from [ADR 0010](./docs/adr/0010-postgres-persistence.md).

## Sprint 7 — Hardening, security review, OpenSSF Scorecard pass

## Sprint 8 — 0.1.0 release, public docs, demo data
