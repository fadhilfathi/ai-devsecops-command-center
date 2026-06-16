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

Status: **planned**.

- Wire the live `KubernetesProvider` using
  `@kubernetes/client-node`.
- Add Prometheus metrics to every service.
- Move the cluster registry, chain repository, and
  correlation buffer to Postgres.
- Add network-policy inference and Istio / Linkerd
  service-mesh edge discovery to the topology engine.
- Replace the heuristic utilisation estimates in the cost
  engine with real Prometheus queries.
- Upgrade the PDF report formatter (charts, headers,
  footers).

## Sprint 6 — Compliance automation

- Auto-mapping of K8s runtime risks to CIS / NIST controls.
- Evidence attachment from inventory, health, and runtime
  services.
- Continuous compliance scoring per cluster / per tenant.

## Sprint 7 — Hardening, security review, OpenSSF Scorecard pass

## Sprint 8 — 0.1.0 release, public docs, demo data
