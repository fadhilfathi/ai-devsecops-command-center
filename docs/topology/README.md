# Topology

The topology service produces three pre-computed graph
views over the tenant's Kubernetes inventory, plus a
per-namespace view and a cross-namespace relationships
endpoint.

## Views

### 1. Service Map

Nodes: services + the workloads they select.
Edges: `service.SELECTS → workload`.

### 2. Application Graph

Nodes: ingresses + services + workloads.
Edges:

- `ingress.ROUTES_TO → service` (label = `host/path→:port`)
- `service.SELECTS → workload`

This is the view that maps "an external request hits the
ingress, the ingress routes to a service, the service
selects a workload, the workload serves the request".

### 3. Topology Graph

The full graph: cluster, namespace, ingress, service,
workload. Used by the asset graph and the inventory
explorer.

### 4. Per-namespace view

A filtered subgraph of the Topology Graph limited to a
single namespace.

### 5. Namespace relationships

Cross-namespace edges derived from ingress rules that target
a service in another namespace.

## Edge semantics

| Edge kind       | Direction                       | Meaning                              |
| --------------- | ------------------------------- | ------------------------------------ |
| `routes_to`     | ingress → service               | Ingress rule routes traffic to service |
| `selects`       | service → workload              | Service selector matches workload labels |
| `in_namespace`  | cluster → namespace             | Namespace belongs to cluster         |
| `depends_on`    | consumer → producer             | Reversed for the Dependency Graph    |

## Layout

The frontend topology viewer uses a deterministic radial
layout (Sprint 4). Sprint 5 will swap in `dagre` or
`elk.js` for a layered, force-directed layout.

## Endpoints

| Method | Path                                  | Description                |
| ------ | ------------------------------------- | -------------------------- |
| GET    | `/v1/topology/graphs`                 | List saved topology graphs |
| GET    | `/v1/topology/service-map`            | Service Map view           |
| GET    | `/v1/topology/application-graph`      | Application Graph view     |
| GET    | `/v1/topology/graph`                  | Full Topology Graph view   |
| GET    | `/v1/topology/namespace/:name`        | Per-namespace view         |
| GET    | `/v1/topology/namespace-relationships` | Cross-namespace edges    |

## See also

- `docs/kubernetes/` — Kubernetes service endpoints.
- `docs/infrastructure/` — the inventory graph layer.
- `backend/models/infrastructure/topology.model.ts` — the
  canonical Zod schema.
