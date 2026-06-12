# Runbook — RiskCalcHighLatencySmall

> **Alert:** `RiskCalcHighLatencySmall`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (Sprint 2 S2.7)
> **Severity:** ticket (no page; investigate within business hours)
> **SLO target:** `devsecops_risk_calculation_duration_seconds{service="dependency-intel",sbom_size_bucket="small"} p95 ≤ 1s` over 30d
> **Threshold:** p95 > 1s for 5m
> **Owner:** SREEngineer (SLO owner: dependency-intel team)

## What this means

`dependency-intel` (port 4009) is calculating risk for a small SBOM (< 100
components) and the p95 latency is over 1 second. Small SBOMs are supposed
to be sub-second — graph-DB warm, no cold start. This is almost always a
regression in dependency-intel itself, not in the data.

## Triage steps

1. **Confirm scope.** In Grafana → Security Stack dashboard → Risk Calc
   panel, filter `sbom_size_bucket="small"`. Is it *all* small SBOMs, or
   only one tenant / one source? If only one tenant, jump to step 4.
2. **Check dependency-intel health.**
   - `curl http://dependency-intel:4009/readyz` — should return 200
   - `kubectl logs -l app=dependency-intel --tail=200 | grep -i error`
3. **Check graph-DB (Neo4j/PostgreSQL) latency.**
   - Slow graph queries dominate the per-calc budget.
   - `pg_stat_statements` (or Neo4j `CALL dbms.listQueries()`) — look for
     queries > 200ms hitting the `dependency` or `component` tables.
4. **Check for cold start.** If dependency-intel was just redeployed, the
   first batch of small SBOMs will hit cold caches. Wait one batch cycle
   (3m) and re-evaluate. Don't page on a cold start.
5. **Memory pressure.** `kubectl top pod -l app=dependency-intel` —
   if RSS is > 80% of limit, OOMs/GC pauses are the likely cause.
   Consider raising the limit (chart bump + PR).

## Mitigation

- **Short-term:** none required; this is a ticket, not a page. File an
  issue with the p95 graph attached.
- **Long-term:** if p95 > 1s is the *steady state*, raise the bucket
  threshold in §3 of `docs/observability/slos-security-stack.md` (requires
  PlatformArchitect re-sign-off) and open a perf ticket against
  dependency-intel.

## Related

- SLO source: `docs/observability/slos-security-stack.md` §3
- Generic runbook (do not use for triage; this file supersedes it):
  `docs/runbooks/RiskCalcHighLatency.md`
- Per-bucket siblings: `Medium` (5s), `Large` (15s), `Xlarge` (60s),
  `Xxlarge` (300s)
