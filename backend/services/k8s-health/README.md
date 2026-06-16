# @aicc/k8s-health-service

Sprint 4 — Kubernetes health engine.

Provides a deterministic 0..100 health score for every cluster,
namespace, workload, and pod a tenant has onboarded. Detects:

- `CrashLoopBackOff`
- `ImagePullBackOff`
- `OOMKilled`
- Pending pods
- Failed pods
- Restart storms
- Node pressure conditions
- Unschedulable workloads

and produces prioritised remediation recommendations.

## Endpoints

| Method | Path                              | Description                          |
| ------ | --------------------------------- | ------------------------------------ |
| GET    | `/v1/health/clusters`             | Health rollup for every cluster      |
| GET    | `/v1/health/namespaces`           | Health rollup for every namespace    |
| GET    | `/v1/health/workloads`            | Health rollup for every workload     |
| GET    | `/v1/health/pods`                 | Health rollup for every pod          |
| GET    | `/v1/health/clusters/:id`         | Per-cluster detail                   |
| GET    | `/v1/health/issues`               | Cross-cluster issue stream           |
| GET    | `/v1/health/recommendations`      | Cross-cluster recommendation stream  |

The health engine consumes inventory from the
`@aicc/kubernetes-service` (port 4006) via HTTP in production; in
Sprint 4 the in-process `InventoryClient` uses the same fixture
provider so the engine can be developed without running the
kubernetes service.
