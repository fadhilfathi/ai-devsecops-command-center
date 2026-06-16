# @aicc/kubernetes-service

Sprint 4 — Kubernetes integration.

Provides cluster-aware inventory for the AICC platform:

| Endpoint                                | Description                                |
| --------------------------------------- | ------------------------------------------ |
| `GET /v1/kubernetes/clusters`           | All onboarded clusters (tenant-scoped)     |
| `GET /v1/kubernetes/namespaces`         | Namespace inventory (filter by cluster)    |
| `GET /v1/kubernetes/workloads`          | Unified workload list (any kind)           |
| `GET /v1/kubernetes/pods`               | Pod inventory                              |
| `GET /v1/kubernetes/services`           | Service inventory                          |
| `GET /v1/kubernetes/ingresses`          | Ingress inventory                          |
| `GET /v1/kubernetes/deployments`        | Deployment inventory (filter by cluster)   |
| `GET /v1/kubernetes/statefulsets`       | StatefulSet inventory                      |
| `GET /v1/kubernetes/daemonsets`         | DaemonSet inventory                        |
| `POST /v1/kubernetes/test-connection`   | Validate a kubeconfig / token before save  |

The Sprint 4 implementation uses an in-process provider abstraction
(`src/providers/`) so the same handlers serve both the production
read-only Kubernetes client and the test fixtures used by the
integration test suite. A real `@kubernetes/client-node` adapter is
wired in Sprint 5.
