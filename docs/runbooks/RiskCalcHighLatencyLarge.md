# Runbook — RiskCalcHighLatencyLarge

> **Alert:** `RiskCalcHighLatencyLarge`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (Sprint 2 S2.7)
> **Severity:** ticket
> **SLO target:** `devsecops_risk_calculation_duration_seconds{service="dependency-intel",sbom_size_bucket="large"} p95 ≤ 15s` over 30d
> **Threshold:** p95 > 15s for 5m
> **Owner:** SREEngineer (SLO owner: dependency-intel team)

## What this means

`dependency-intel` (port 4009) is calculating risk for a large SBOM
(1,000–9,999 components) and the p95 latency is over 15 seconds. Large
SBOMs are typical for production services (50–500 direct deps, hundreds
to thousands of transitives). The graph has 10k–100k nodes.

## Triage steps

1. **Confirm scope.** Grafana → Security Stack → Risk Calc panel,
   `sbom_size_bucket="large"`. Check whether the regression is fleet-
   wide or only some tenants (e.g. monorepos).
2. **Check graph DB indices.** A missing index on `component(ecosystem,
   version)` is the #1 cause of large-SBOM regression. `EXPLAIN ANALYZE`
   the slowest query in `pg_stat_statements` (or `CALL db.schema.visualize`
   in Neo4j) to verify index usage.
3. **Memory pressure.** Large SBOMs require proportional working set. If
   RSS is at the limit, the OS is swapping and every calc is slow.
   `kubectl top pod -l app=dependency-intel`. Consider raising the limit.
4. **CPU saturation.** `kubectl top pod -l app=dependency-intel` — if CPU
   is at 100% across all replicas, the per-calc work is just outrunning
   the CPU. Scale horizontally (replica +2) while filing a perf ticket.
5. **CVE correlation cost.** Vulnerability correlation is the second
   biggest cost after graph traversal. Check the `vuln-intel:4008`
   latency — if it's also slow, the lag is upstream.

## Mitigation

- **Short-term:** none required (ticket). File an issue with the
  per-tenant p95 graph and the slow-query log.
- **Long-term:** add the missing graph index; raise the dep-intel memory
  limit from 1Gi → 2Gi; consider precomputing transitive risk scores for
  hot monorepos.

## Related

- SLO source: `docs/observability/slos-security-stack.md` §3
- Per-bucket siblings: `Small` (1s), `Medium` (5s), `Xlarge` (60s),
  `Xxlarge` (300s)
