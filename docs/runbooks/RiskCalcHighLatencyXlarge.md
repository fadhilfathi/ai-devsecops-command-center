# Runbook — RiskCalcHighLatencyXlarge

> **Alert:** `RiskCalcHighLatencyXlarge`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (Sprint 2 S2.7)
> **Severity:** ticket
> **SLO target:** `devsecops_risk_calculation_duration_seconds{service="dependency-intel",sbom_size_bucket="xlarge"} p95 ≤ 60s` over 30d
> **Threshold:** p95 > 60s for 5m
> **Owner:** SREEngineer (SLO owner: dependency-intel team)

## What this means

`dependency-intel` (port 4009) is calculating risk for an xlarge SBOM
(10,000–49,999 components) and the p95 latency is over 60 seconds. Xlarge
SBOMs are typically large monorepos, complex applications, or OS-package
sprawls. The graph has 100k–1M nodes; transitive chains can be 20+ deep.

## Triage steps

1. **Confirm scope.** Grafana → Security Stack → Risk Calc panel,
   `sbom_size_bucket="xlarge"`. Identify the top 3 tenants by p95. Are
   they the same ones we expect (monorepos), or a new tenant is hitting
   the bucket for the first time?
2. **Check for runaway jobs.** A single xlarge calc that doesn't
   terminate in 5m is a runaway — check
   `devsecops_active_scans{service="dependency-intel",status="running"}`
   in Grafana. If count > N (replicas × 2), the worker pool is
   saturated. Consider killing the oldest jobs.
3. **Deep transitive chains.** N+1 graph queries at 20+ depth are the
   primary cost driver. Check `pg_stat_statements` for recursive CTE
   plans; consider depth-bounding the traversal to 10.
4. **Memory ceiling.** xlarge SBOMs need ≥ 2Gi RSS. If dep-intel limit
   is 1Gi, swap is the cause. Bump to 4Gi via Helm values.
5. **CPU.** If CPU is saturated across all replicas, horizontal scale
   is the only short-term fix. `kubectl scale deploy/dependency-intel
   --replicas=6` (default is 3) and re-evaluate.

## Mitigation

- **Short-term:** kill runaway jobs; scale dep-intel replicas +2;
  raise memory limit; file a perf ticket.
- **Long-term:** depth-bound graph traversal to 10; add a precomputed
  transitive-risk cache; consider splitting xlarge calcs into
  background workers and surfacing partial results.

## Related

- SLO source: `docs/observability/slos-security-stack.md` §3
- Per-bucket siblings: `Small` (1s), `Medium` (5s), `Large` (15s),
  `Xxlarge` (300s)
