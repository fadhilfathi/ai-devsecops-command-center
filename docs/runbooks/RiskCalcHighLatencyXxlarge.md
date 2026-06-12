# Runbook — RiskCalcHighLatencyXxlarge

> **Alert:** `RiskCalcHighLatencyXxlarge`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (Sprint 2 S2.7)
> **Severity:** ticket
> **SLO target:** `devsecops_risk_calculation_duration_seconds{service="dependency-intel",sbom_size_bucket="xxlarge"} p95 ≤ 300s` over 30d
> **Threshold:** p95 > 300s for 10m
> **Owner:** SREEngineer (SLO owner: dependency-intel team)

## What this means

`dependency-intel` (port 4009) is calculating risk for an xxlarge SBOM
(≥ 50,000 components) and the p95 latency is over 5 minutes. Xxlarge
SBOMs are OS container images, full Linux distributions, or giant
monorepos. The graph has 1M+ nodes; transitive chains can be 30+ deep.

This is a soft-real-time signal: the SLO is generous (5 min) because
xxlarge calcs are expected to be slow. The 10m `for:` window is
deliberate — we want to ignore transient blips, not the steady state.

## Triage steps

1. **Confirm it's real xxlarge, not a misclassified bucket.** Grafana →
   Security Stack → Risk Calc panel, `sbom_size_bucket="xxlarge"`. If
   the SBOM is < 50k components, the bucket label is wrong — file a
   bug against dependency-intel.
2. **Identify the SBOM.** xxlarge calcs are expensive; they should be
   cached or precomputed. Check
   `devsecops_active_scans{service="dependency-intel",sbom_size_bucket="xxlarge"}`
   — if a single tenant is dominating, that's the one to investigate.
3. **Check for a true runaway.** A single xxlarge calc that hasn't
   terminated in 30m is a runaway. Kill it via the admin API
   (`POST /admin/calcs/{calc_id}/cancel`). Don't wait for the SLO to
   fire — the cost is real.
4. **Memory / disk.** xxlarge graphs may need 8Gi+ RSS and significant
   temp disk (graph cache). Check `kubectl top pod` and
   `kubectl exec ... df -h /tmp`. If `/tmp` is full, the graph cache is
   spilling and the calc is reading from cold disk.
5. **Horizontal scale.** xxlarge calcs are CPU-bound and embarrassingly
   parallel across SBOMs. If the queue is growing
   (`devsecops_queue_depth{queue="risk_calc_jobs"}` > 10), scale
   dep-intel to 8–10 replicas.

## Mitigation

- **Short-term:** kill runaways; precompute and cache xxlarge calcs
  for the top 5 tenants; raise dep-intel memory limit to 8Gi.
- **Long-term:** this bucket is the most likely candidate for a
  relaxed SLO (e.g. 600s) or a batch-only mode (calc on a schedule, not
  on demand). Discuss with PlatformArchitect at the next SLO review.

## Related

- SLO source: `docs/observability/slos-security-stack.md` §3
- Per-bucket siblings: `Small` (1s), `Medium` (5s), `Large` (15s),
  `Xlarge` (60s)
