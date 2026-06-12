# Runbook — RiskCalcHighLatencyXs

**Alert:** `RiskCalcHighLatencyXs`
**Severity:** ticket
**Service:** `dependency-intel` (port 4009)
**Source metric:** `devsecops_risk_calculation_duration_seconds_bucket{service="dependency-intel",sbom_size_bucket="xs"}`
**PromQL:**
```promql
histogram_quantile(0.95,
  sum by (le) (rate(devsecops_risk_calculation_duration_seconds_bucket{service="dependency-intel",sbom_size_bucket="xs"}[5m]))
) > 0.5
```
**Locked in:** S2.7 round 6 (D7 5-bucket scheme, 2026-06-12)

---

## What this means

The `devsecops_risk_calculation_duration_seconds` histogram is bucketing
the p95 latency for SBOMs with **fewer than 10 components** (`xs` bucket)
at above 0.5s for 5+ minutes. SBOMs this small should be processed in
**sub-100ms in steady state** — 0.5s is the cold-start budget, not the
expected p95. The alert indicates the dependency-intel service is doing
unnecessary work for trivially-small SBOMs.

This is a **new bucket** introduced in S2.7 round 6 (D7 5-bucket scheme
replaces the round-5 small/medium/large/xlarge/xxlarge scheme). The
`xxlarge` bucket is **retired** — its runbook stub is kept for
reference but the alert is no longer emitted.

## Likely causes

1. **Cold-start / warm-up.** The first few risk-calculation calls after
   a service restart can be slow due to graph-DB connection setup,
   JIT compilation, or OTel SDK initialization. Expected to clear within
   5-10 minutes. If not, escalate.
2. **Graph-DB connection-pool starvation.** The dependency-intel service
   uses a connection pool to the graph store. If the pool is exhausted
   (e.g., a long-running `xlarge` calculation is hogging all connections),
   even trivially-small SBOMs will queue. Check active queries with
   `pg_stat_activity` (Postgres) or equivalent.
3. **Memory pressure / GC.** A Java/Python GC pause can spike
   `dependency-intel`'s p95 latency across all buckets — check this alert
   in conjunction with `RiskCalcHighLatencyMedium` or `RiskCalcHighLatencyLarge`
   to see if the issue is `xs`-specific or global.
4. **OTel SDK overhead.** The OpenTelemetry SDK adds 1-5ms per
   metric emission. For sub-10-component SBOMs where the calculation
   itself takes 1-5ms, OTel overhead can dominate. Check that the
   `OTEL_TRACES_SAMPLER` and `OTEL_METRICS_EXPORTER` env vars are
   configured to skip high-cardinality labels.

## Triage steps

1. **Confirm it's not a cold-start.** Check service uptime:
   ```bash
   kubectl get pods -n devsecops -l app=dependency-intel -o jsonpath='{.items[*].status.containerStatuses[*].state.running.startedAt}'
   ```
   If the pod started within the last 10 minutes, this is likely a
   cold-start and will self-resolve. If not, continue.
2. **Check graph-DB health.** For Neo4j:
   ```cypher
   CALL dbms.listQueries() YIELD query, elapsedTimeMillis
   WHERE elapsedTimeMillis > 1000
   RETURN query, elapsedTimeMillis
   ```
   For Postgres-based graphs (the default for S2.3):
   ```sql
   SELECT pid, state, query_start, NOW() - query_start AS duration, query
   FROM pg_stat_activity
   WHERE state != 'idle' AND NOW() - query_start > INTERVAL '1 second'
   ORDER BY duration DESC;
   ```
3. **Check dependency-intel p95 across all buckets** to see if this is
   `xs`-specific or global:
   ```promql
   histogram_quantile(0.95,
     sum by (le, sbom_size_bucket) (
       rate(devsecops_risk_calculation_duration_seconds_bucket{service="dependency-intel"}[5m])
     )
   )
   ```
   If only `xs` is elevated, the issue is local to small-graph processing
   (likely cause 2 or 4). If all buckets are elevated, it's a global issue
   (likely cause 3 or a general outage).
4. **Check `xs` workload volume.** If `xs` SBOMs suddenly spiked (e.g.,
   a fleet of trivially-small monorepo components being scanned), the
   graph-DB connection pool may be saturated by sheer concurrency:
   ```promql
   sum(rate(devsecops_risk_calculation_duration_seconds_count{service="dependency-intel",sbom_size_bucket="xs"}[5m]))
   ```
   Compare to baseline.
5. **Check OTel SDK configuration** in the dependency-intel deployment
   manifest. Ensure `OTEL_METRIC_EXPORT_INTERVAL=60000` (60s, not 1s)
   and `OTEL_BSP_SCHEDULE_DELAY=5000` (5s batch span processor delay).

## Remediation

- **Cold-start:** wait. If it persists past 10 minutes, follow the
  general cold-start runbook at `docs/runbooks/dependency-intel-cold-start.md`.
- **Connection-pool starvation:** increase the graph-DB connection-pool
  size in `dependency-intel`'s deployment manifest. Default is 10; raise
  to 25 if the `xlarge` workload is sustained. **Coordinate with
  PlatformArchitect** before changing infrastructure defaults.
- **Memory pressure / GC:** check `dependency-intel` heap metrics. If
  heap usage is above 80% sustained, consider increasing the JVM
  `-Xmx` or Python process memory limit.
- **OTel SDK overhead:** confirm the OTel SDK is in batch mode (not
  simple/streaming) and that high-cardinality labels are not being
  emitted on every span.

## Escalation

If p95 > 2s sustained for 15+ minutes, escalate to:
1. **SRE on-call** — page via PagerDuty
2. **PlatformArchitect** — for graph-DB tuning or capacity planning
3. **SecurityArchitect** — if the latency is causing a downstream
   security regression (e.g., CVE detection delay)

## Related alerts

- `RiskCalcHighLatency` (global, p95 > 10s for 10m) — coarse early warning
- `RiskCalcHighLatencySmall` (per-bucket, 10–99 components)
- `RiskCalcHighLatencyMedium` (per-bucket, 100–999 components)
- `RiskCalcHighLatencyLarge` (per-bucket, 1k–4,999 components)
- `RiskCalcHighLatencyXlarge` (per-bucket, ≥5k components; absorbs former xxlarge)
- ~~`RiskCalcHighLatencyXxlarge`~~ — **retired round 6** (former ≥50k bucket; runbook stub kept for reference)

## References

- SLO doc: `docs/observability/slos-security-stack.md` §3
- Metrics spec: `docs/observability/metrics-spec.md` §3.3
- Alert rule: `infra/observability/prometheus/alert-rules.yml` (security_stack.runtime group)
- D7 amendment history: `docs/observability/slos-security-stack.md` §6 round 6
