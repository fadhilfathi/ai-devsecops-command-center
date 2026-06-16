# Infrastructure

The infrastructure workstream unifies the tenant's clusters,
namespaces, services, deployments, and supporting resources
into a single asset graph that powers the Infrastructure
Overview, Cluster / Namespace / Workload explorers, and the
inventory relationships and dependency graph endpoints.

## Architecture

The workstream is split into four services:

- **`kubernetes-service`** (port 4006) — the read-only
  inventory layer. Wraps a provider abstraction that can be
  swapped between the in-process `fixture` provider (Sprint
  4) and a live `@kubernetes/client-node` adapter (Sprint 5).
- **`inventory-service`** (port 4009) — the asset catalog,
  relationship graph, and dependency graph.
- **`k8s-health-service`** (port 4007) — health scoring +
  detection rules.
- **`reporting-service`** (port 4012) — generates the
  Cluster Health, Infrastructure Risk, and Executive Summary
  reports.

## Data model

The inventory uses a three-layer abstraction:

1. **Provider** — translates the K8s API to the AICC model.
2. **InventorySnapshot** — a flat snapshot of all
   cluster-scoped resources at a moment in time.
3. **Asset / Topology** — the catalog and graph layers built
   on top of the snapshot.

The model layer lives at
`backend/models/infrastructure/`. The Zod schemas are the
single source of truth for the wire contract; the
TypeScript types in `frontend/src/types/infrastructure.ts`
mirror them.

## Asset kinds

| Kind         | Source                                |
| ------------ | ------------------------------------- |
| cluster      | `Cluster` model                       |
| namespace    | `Namespace` model                     |
| service      | `Service` model                       |
| deployment   | `Deployment` model                    |
| statefulset  | `StatefulSet` model                   |
| daemonset    | `DaemonSet` model                     |
| ingress      | `Ingress` model                       |
| workload     | generic union of deployment/ss/ds     |
| pod          | `Pod` model                           |

## Graph model

The graph layer exposes two views:

- **Relationship Graph** — top-down: cluster contains
  namespace, service selects workload, ingress routes_to
  service.
- **Dependency Graph** — same edges reversed: workload
  depends_on service, service depends_on ingress, etc.
  This is the orientation the topology viewer's layout
  engine reads as "up".

Per-asset `dependenciesFor(assetId)` returns the transitive
closure of the dependency subgraph rooted at the asset —
useful for blast-radius analysis.

## See also

- `docs/kubernetes/` — Kubernetes service endpoints.
- `docs/topology/` — the topology viewer + edge semantics.
- `docs/cost-optimization/` — the cost engine that consumes
  the same inventory.
- `docs/architecture/sprint-4/` — Sprint 4 architecture
  notes.
