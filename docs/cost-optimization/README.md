# Cost Optimization

Sprint 4 introduces a Kubernetes cost intelligence service
that analyses workload resource requests and limits, detects
waste, and produces prioritised optimisation recommendations
with projected savings.

## Pricing

The cost engine uses a configurable per-unit USD price model:

| Dimension | Default (USD/hour)   | Note                         |
| --------- | -------------------- | ---------------------------- |
| CPU       | 0.041                | ~$30/month per vCPU          |
| Memory    | 0.005                | ~$3.60/month per GiB         |
| GPU       | 2.50                 | Reserved for Sprint 5        |
| Network   | 0.00                 | Off by default; egress-tier  |

Override via env vars `AICC_COST_CPU_USD_PER_HOUR` and
`AICC_COST_MEMORY_USD_PER_HOUR`.

Monthly cost is computed as `price × vCPU-hour × 730` (or
`GiB-hour × 730`). Recommended cost is computed against a
target 80% p95 utilisation, with a 1.25× safety headroom and
rounding up to the nearest 10m CPU / 64 MiB memory.

## Finding taxonomy

| Finding kind                  | Default severity | Trigger                                      |
| ----------------------------- | ---------------- | -------------------------------------------- |
| over_provisioned_cpu          | medium / high    | CPU p95 ≪ request (heuristic, Sprint 5: data)|
| over_provisioned_memory       | medium / high    | Memory p95 ≪ request                         |
| under_utilized_cpu            | medium           | CPU p95 < 30% of request                     |
| under_utilized_memory         | medium           | Memory p95 < 30% of request                  |
| missing_requests              | medium           | No CPU/memory requests                       |
| missing_limits                | low              | No CPU/memory limits                         |
| noisy_neighbour               | low              | Limit / request ratio > 4×                   |
| cold_workload                 | low              | p95 < 5% on both dimensions                  |

## Recommendations

The engine emits a `CostRecommendation` per action, with
priority `p0` (critical) → `p3` (low), a projected monthly
and annual savings, and a free-form `actionPayload` (a hint
for the operator or a future GitOps controller).

| Action                       | Description                              |
| ---------------------------- | ---------------------------------------- |
| right_size_requests          | Lower requests to match p95              |
| right_size_limits            | Tighten limits to avoid noisy neighbour  |
| add_requests                 | Add CPU/memory requests                  |
| add_limits                   | Add CPU/memory limits                    |
| remove_unused_workload       | Decommission or scale to zero            |
| consolidate_replicas         | (Sprint 5)                               |
| use_spot_or_preemptible      | (Sprint 5)                               |

## Endpoints

| Method | Path                                | Description                          |
| ------ | ----------------------------------- | ------------------------------------ |
| GET    | `/v1/cost/analysis`                 | Per-cluster / tenant cost analysis   |
| GET    | `/v1/cost/analysis/cluster/:id`     | Per-cluster cost analysis            |
| GET    | `/v1/cost/workloads`                | Per-workload cost breakdown          |
| GET    | `/v1/cost/findings`                 | Waste / over-provisioning findings   |
| GET    | `/v1/cost/recommendations`          | Optimisation recommendations         |

## See also

- `docs/kubernetes/` — Kubernetes service endpoints.
- `docs/infrastructure/` — the inventory layer that feeds
  the cost engine.
- `backend/models/infrastructure/cost-analysis.model.ts` —
  the canonical Zod schema.
