# @aicc/topology-service

Sprint 4 — Topology Engine.

Builds three pre-computed topology views over the tenant's
Kubernetes inventory:

- **Service Map** — services and the workloads they select,
  one node per Service and per Workload.
- **Application Graph** — ingresses + services + workloads,
  with the edge from ingress to service labeled with the
  host + path.
- **Topology Graph** — full graph (clusters, namespaces,
  services, workloads, ingresses, pods).

All three views are returned in the unified `TopologyGraph`
shape (`{ nodes, edges }`) so the frontend topology viewer
can render any of them without re-wiring.

## Endpoints

| Method | Path                                            | Description                          |
| ------ | ----------------------------------------------- | ------------------------------------ |
| GET    | `/v1/topology/graphs`                           | List saved topology graphs           |
| GET    | `/v1/topology/service-map`                      | Service Map view                     |
| GET    | `/v1/topology/application-graph`                | Application Graph view               |
| GET    | `/v1/topology/graph`                            | Full Topology Graph view             |
| GET    | `/v1/topology/namespace/:name`                  | Per-namespace view                   |
| GET    | `/v1/topology/namespace-relationships`          | Cross-namespace edge list            |
