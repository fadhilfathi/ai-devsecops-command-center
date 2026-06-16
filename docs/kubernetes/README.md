# Kubernetes

Sprint 4 introduces the Kubernetes & Infrastructure Intelligence
workstream. The platform now understands clusters, namespaces,
workloads, pods, services, ingresses, deployments, statefulsets,
and daemonsets — read-only, tenant-scoped, multi-cluster.

## Services

| Service                                | Port | Purpose                                   |
| -------------------------------------- | ---- | ----------------------------------------- |
| `@aicc/kubernetes-service`             | 4006 | Read-only K8s inventory                   |
| `@aicc/k8s-health-service`             | 4007 | Health scoring + recommendations          |
| `@aicc/runtime-security-service`       | 4008 | Runtime security findings + reports       |
| `@aicc/inventory-service`              | 4009 | Unified asset catalog + graph             |
| `@aicc/cost-intelligence-service`      | 4010 | Cost analysis + recommendations           |
| `@aicc/topology-service`               | 4011 | Service Map / Application Graph / Topology Graph |
| `@aicc/reporting-service`              | 4012 | 6 reports × {json, md, pdf}               |

## Core concepts

- **Cluster** — an onboarded Kubernetes cluster. Each tenant
  may have multiple clusters. The cluster is the inventory
  root.
- **Namespace** — a security / RBAC boundary inside a cluster.
  Inventory, health, and cost can be filtered by namespace.
- **Workload** — abstract deployable unit: Deployment,
  StatefulSet, DaemonSet, ReplicaSet, CronJob, Job, Pod.
- **Pod** — the smallest deployable unit; the natural point
  for both health and runtime-security observation.
- **Service** — a stable virtual IP / DNS name that fronts
  a set of pods. The Application Graph's *depends_on* edges
  terminate at services.
- **Ingress** — the layer-7 routing object; the source of
  *routes_to* edges.
- **Asset** — a generic inventory item; the inventory
  service flattens the K8s hierarchy into a list of assets
  with `kind` discriminator.

## Endpoints (summary)

| Method | Path                                                | Service                |
| ------ | --------------------------------------------------- | ---------------------- |
| GET    | `/v1/kubernetes/clusters`                           | kubernetes-service     |
| GET    | `/v1/kubernetes/namespaces`                         | kubernetes-service     |
| GET    | `/v1/kubernetes/workloads`                          | kubernetes-service     |
| GET    | `/v1/kubernetes/pods`                               | kubernetes-service     |
| GET    | `/v1/kubernetes/services`                           | kubernetes-service     |
| GET    | `/v1/kubernetes/ingresses`                          | kubernetes-service     |
| GET    | `/v1/kubernetes/deployments`                        | kubernetes-service     |
| GET    | `/v1/kubernetes/statefulsets`                       | kubernetes-service     |
| GET    | `/v1/kubernetes/daemonsets`                         | kubernetes-service     |
| POST   | `/v1/kubernetes/test-connection`                    | kubernetes-service     |
| GET    | `/v1/health/clusters`                               | k8s-health-service     |
| GET    | `/v1/health/namespaces`                             | k8s-health-service     |
| GET    | `/v1/health/workloads`                              | k8s-health-service     |
| GET    | `/v1/health/pods`                                   | k8s-health-service     |
| GET    | `/v1/health/issues`                                 | k8s-health-service     |
| GET    | `/v1/health/recommendations`                        | k8s-health-service     |
| GET    | `/v1/runtime-security/rules`                        | runtime-security-service |
| GET    | `/v1/runtime-security/risks`                        | runtime-security-service |
| POST   | `/v1/runtime-security/scan`                         | runtime-security-service |
| GET    | `/v1/runtime-security/report`                       | runtime-security-service |
| GET    | `/v1/inventory/assets`                              | inventory-service      |
| GET    | `/v1/inventory/graph/asset`                         | inventory-service      |
| GET    | `/v1/inventory/graph/relationships`                 | inventory-service      |
| GET    | `/v1/inventory/graph/dependencies`                  | inventory-service      |
| GET    | `/v1/cost/analysis`                                 | cost-intelligence-service |
| GET    | `/v1/cost/workloads`                                | cost-intelligence-service |
| GET    | `/v1/cost/findings`                                 | cost-intelligence-service |
| GET    | `/v1/cost/recommendations`                          | cost-intelligence-service |
| GET    | `/v1/topology/graphs`                               | topology-service       |
| GET    | `/v1/topology/service-map`                          | topology-service       |
| GET    | `/v1/topology/application-graph`                    | topology-service       |
| GET    | `/v1/topology/graph`                                | topology-service       |
| GET    | `/v1/topology/namespace/:name`                      | topology-service       |
| GET    | `/v1/reports/cluster-health`                        | reporting-service      |
| GET    | `/v1/reports/infrastructure-risk`                   | reporting-service      |
| GET    | `/v1/reports/runtime-security`                      | reporting-service      |
| GET    | `/v1/reports/cost-optimization`                     | reporting-service      |
| GET    | `/v1/reports/topology`                              | reporting-service      |
| GET    | `/v1/reports/executive-summary`                     | reporting-service      |

## Multi-tenancy

Every endpoint is tenant-scoped via the `x-tenant-id` header
(or a JWT-derived tenant at the gateway). The fixture provider
in Sprint 4 returns the same per-tenant data shape as the
production K8s API will in Sprint 5.

## See also

- `docs/infrastructure/` — design notes for the inventory,
  cost, and topology engines.
- `docs/runtime-security/` — the runtime-security rule set.
- `docs/cost-optimization/` — the cost-engine model and
  recommendations.
- `docs/topology/` — the topology graph model.
- `docs/architecture/sprint-4/` — the Sprint 4 architecture
  notes.
