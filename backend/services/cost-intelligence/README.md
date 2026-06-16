# @aicc/cost-intelligence-service

Sprint 4 — Kubernetes Cost Intelligence.

Analyses workload resource requests and limits, detects waste,
over-provisioning, and under-utilization, and produces cost
optimization recommendations with projected savings.

## Endpoints

| Method | Path                                            | Description                          |
| ------ | ----------------------------------------------- | ------------------------------------ |
| GET    | `/v1/cost/analysis`                             | Per-cluster / tenant cost analysis   |
| GET    | `/v1/cost/analysis/cluster/:id`                 | Per-cluster cost analysis            |
| GET    | `/v1/cost/workloads`                            | Per-workload cost breakdown          |
| GET    | `/v1/cost/findings`                             | Waste / over-provisioning findings   |
| GET    | `/v1/cost/recommendations`                      | Optimisation recommendations         |
