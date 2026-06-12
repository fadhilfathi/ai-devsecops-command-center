# Runbook — RiskCalcHighLatencyMedium

> **Alert:** `RiskCalcHighLatencyMedium`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (Sprint 2 S2.7)
> **Severity:** ticket
> **SLO target:** `devsecops_risk_calculation_duration_seconds{service="dependency-intel",sbom_size_bucket="medium"} p95 ≤ 5s` over 30d
> **Threshold:** p95 > 5s for 5m
> **Owner:** SREEngineer (SLO owner: dependency-intel team)

## What this means

`dependency-intel` (port 4009) is calculating risk for a medium SBOM
(100–999 components) and the p95 latency is over 5 seconds. Medium SBOMs
have ~1k–10k nodes in the graph; cold cache or graph-DB N+1 patterns are
the usual suspects.

## Triage steps

1. **Confirm scope.** Grafana → Security Stack → Risk Calc panel,
   `sbom_size_bucket="medium"`. Fleet-wide or single tenant?
2. **Check dependency-intel /readyz.** 200 expected.
3. **Cold cache detection.** Look at the `devsecops_risk_calculation_
   duration_seconds_bucket` histogram in Grafana Explore. If the bucket
   `0.5–1` is empty and `5–10` is full, the cache is cold and warming up
   will help. Consider raising the in-process LRU size or pre-warming
   per-tenant on SBOM ingest.
4. **GC pause check.** `kubectl logs -l app=dependency-intel | grep -i
   "gc\|gc-pause"` — Python services use gunicorn; long GC pauses show
   as 5–10s gaps in request logs.
5. **Graph DB N+1.** `pg_stat_statements` — if the same SELECT runs
   thousands of times per risk calc, you have an N+1. File a perf ticket.

## Mitigation

- **Short-term:** none required (ticket, not page).
- **Long-term:** if sustained, add a graph-DB connection pool with
  pre-warmed statement cache; bump the dependency-intel replica count
  by 2× to spread the load; review the risk-calc algorithm for N+1.

## Related

- SLO source: `docs/observability/slos-security-stack.md` §3
- Per-bucket siblings: `Small` (1s), `Large` (15s), `Xlarge` (60s),
  `Xxlarge` (300s)
