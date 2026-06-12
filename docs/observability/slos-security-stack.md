# SLO Targets — Sprint 2 Security Stack

> **Owner:** SREEngineer
> **Sprint:** 2 — Security Stack
> **Status:** **Locked v1.0** (PlatformArchitect sign-off 2026-06-12)
> **Last Updated:** 2026-06-12 (post sign-off)
> **Sign-off message:** from PlatformArchitect, slot 019ebae2-9df9-7db0-a45b-c36d235b811e
> **Companions:** `slo-sli-definitions.md`, `alerting-runbooks.md`, `metrics-spec.md` (PlatformArchitect — cross-link target)
> **Sign-off deadline:** 2026-06-13 12:00 UTC — **MET** (2026-06-12)

This document specifies the **SLO targets** for the three Sprint 2 metrics
that PlatformArchitect flagged as needing SRE sign-off before they finalize
the platform SLI doc (`docs/observability/metrics-spec.md`).

## 1. SLO framework reminder

- **Window:** rolling **30 days** for all SLOs.
- **Target format:** `0.XX` (e.g., 0.95 = 95% within target).
- **Budget:** `(1 - target) × window_minutes`.
- **Burn alerts:** multi-window, multi-burn-rate (see `alerting-runbooks.md` §3).

## 2. `devsecops_sbom_generation_duration_seconds` p99 targets

**Per-`target_type` SLOs (95% of generations complete within the target):**

| `target_type` | p99 target (95% SLO) | Rationale |
|---|---|---|
| `image`       | 60 s   | Image scans pull layers + do package detection; most are < 30s, p99 dominated by large/distroless images. |
| `filesystem`  | 30 s   | Local FS walk; fast path. |
| `directory`   | 30 s   | Same as `filesystem`; aliased for clarity. |
| `archive`     | 60 s   | tar/zip extract + parse; can be slow on large archives. |
| `repo`        | 120 s  | git clone + parse; network-bound. |

**Aggregate SLO:** 95% of all generations, regardless of `target_type`, complete
within **60 s** (the most common target). 99% within **180 s** (safety net for repos).

**Burn alerts (derived from this SLO):**
- **Fast burn (page):** 14.4× burn over 1h AND 6h windows.
- **Slow burn (ticket):** 1× burn over 24h AND 3d windows.

**Calibration note:** the existing `ScanQueueBacklog` alert (depth > 100, 15m)
catches capacity problems; these new p99 alerts catch *per-request* performance
regressions that may not surface as a backlog for several hours.

## 3. `devsecops_risk_calculation_duration_seconds` p99 targets

**Per-`sbom_size_bucket` SLOs (95% of calculations complete within the target):**

| `sbom_size_bucket` | Component range        | p99 target (95% SLO) | Rationale |
|---|---|---|---|
| `small`            | < 100                  | 1 s   | Trivial graph traversal. |
| `medium`           | 100 – 999              | 5 s   | Sub-second in practice; budget is for cold cache / GC. |
| `large`            | 1,000 – 9,999          | 15 s  | Graph build + transitive risk propagation. |
| `xlarge`           | 10,000 – 49,999        | 60 s  | Risk propagation O(V+E); p99 dominated by deep transitive chains. |
| `xxlarge`          | ≥ 50,000               | 300 s | Full OS images and monorepos; 5–10× slower than `xlarge` per PlatformArchitect. |

**Per-`algorithm` notes:**
- `cvss_only` is the fastest (no external lookups).
- `cvss_epss` adds a Redis lookup; expect +50–200 ms p99.
- `cvss_epss_kev` adds a CISA KEV catalog lookup; expect +100–500 ms p99.
- `full` runs all of the above plus a graph-closure pass; expect 2–5× the `cvss_only` baseline.

The SLOs above are calibrated against the **`cvss_epss`** algorithm; teams
running `full` for security-critical SBOMs should expect to overshoot and
should provision accordingly (more replicas, or schedule `full` runs off-peak).

**Per-bucket burn alerts (new this turn):**
- `RiskCalcHighLatencySmall` — p95 of `small` bucket > 1 s for 5 min
- `RiskCalcHighLatencyMedium` — p95 of `medium` bucket > 5 s for 5 min
- `RiskCalcHighLatencyLarge` — p95 of `large` bucket > 15 s for 5 min
- `RiskCalcHighLatencyXlarge` — p95 of `xlarge` bucket > 60 s for 5 min
- `RiskCalcHighLatencyXxlarge` — p95 of `xxlarge` bucket > 300 s for 10 min

These are added in `infra/observability/prometheus/alert-rules.yml` under
a new `security_stack.risk_calc_per_bucket` group. The existing
`RiskCalcHighLatency` (global p95 > 10 s) is retained as a coarse
early-warning signal; per-bucket alerts give the actionable detail.

## 4. `devsecops_eventbus_lag_seconds` p99 target (CONFIRM)

**Target:** **5 s** (PlatformArchitect's proposal — **confirmed by SREEngineer**).

| Threshold | Action |
|---|---|
| p99 lag < 5 s  for 10 min | OK (within SLO) |
| p99 lag ≥ 5 s  for 10 min | **Page** (fast burn: SLO breached) |
| p99 lag ≥ 30 s for 5 min  | **Critical page** (3× over SLO; consumers falling badly behind) |
| p99 lag ≥ 60 s for 5 min  | **Page on-call lead** (4× over SLO; pipeline stalled) |

**Per-`stream` SLOs (suggested; finalize with PlatformArchitect):**
- `security.events` — p99 < 5 s (critical security events must propagate fast)
- `compliance.events` — p99 < 30 s (compliance is not real-time critical)
- `audit.events` — p99 < 60 s (audit is asynchronous; high lag is acceptable for volume reasons)

**Aggregate platform SLI:** p99 lag across all streams < 5 s. Computed as
`histogram_quantile(0.99, sum(rate(devsecops_eventbus_lag_seconds_bucket[5m])) by (le))`.

## 5. SLO summary table

| Metric                                              | SLO (95% within) | Window  | Page threshold |
|-----------------------------------------------------|------------------|---------|----------------|
| `devsecops_sbom_generation_duration_seconds` (image) | 60 s            | 30d     | 14.4× burn, 1h & 6h |
| `devsecops_sbom_generation_duration_seconds` (repo)  | 120 s           | 30d     | 14.4× burn, 1h & 6h |
| `devsecops_sbom_generation_duration_seconds` (all)   | 60 s            | 30d     | 14.4× burn, 1h & 6h |
| `devsecops_risk_calculation_duration_seconds` (small) | 1 s           | 30d     | p95 > 1 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (medium) | 5 s          | 30d     | p95 > 5 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (large) | 15 s           | 30d     | p95 > 15 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (xlarge) | 60 s          | 30d     | p95 > 60 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (xxlarge) | 300 s        | 30d     | p95 > 300 s, 10m |
| `devsecops_eventbus_lag_seconds`                    | 5 s             | 30d     | p99 > 5 s, 10m |
| `devsecops_eventbus_lag_seconds` (critical)         | 30 s            | 30d     | p99 > 30 s, 5m |

## 6. Sign-off & open items

**PlatformArchitect sign-off (2026-06-12):** all 4 open questions **APPROVED**.

- **Q1 — Per-`target_type` SBOM SLOs + global fallback:** ✅ APPROVED. Different
  Syft code paths justify per-`target_type` targets. Global kept as fleet-wide
  coarse signal.
- **Q2 — Per-`sbom_size_bucket` risk-calc SLOs:** ✅ APPROVED. Weighted single
  SLO would mask `xlarge`/`xxlarge` tails where user pain lives.
- **Q3 — `compliance.events` (30s) and `audit.events` (60s) lag SLOs:** ✅ APPROVED.
  Audit log durability is independent of bus lag; stick with 60s (not 120s) for UX.
- **Q4 — Uniform vs service-specific SLOs:** ✅ APPROVED. Uniform is correct
  for Sprint 2; revisit at end of Sprint 3 with 30d baseline.

**3 follow-up items (F1–F3), all queued:**

- **F1 — Multi-window burn-rate alerts (Google SRE workbook).** TODO marker
  added in `infra/observability/prometheus/alert-rules.yml` near the
  `security_stack.runtime` group. Full implementation queued for Sprint 3
  (per-platform burn-rate SLOs need a baseline first; we don't have 30d
  telemetry yet).
- **F2 — Per-alert `runbook_url` annotations + per-bucket runbook stubs.**
  All 9 S2.7 alerts in `alert-rules.yml` now have `runbook_url`
  annotations. The 5 per-bucket `RiskCalcHighLatency*` alerts have their
  own runbook files: `docs/runbooks/RiskCalcHighLatency{Small,Medium,
  Large,Xlarge,Xxlarge}.md`.
- **F3 — `histogram_quantile()` aggregation safety note.** Added below in
  §7. Reminder: always `sum by (le, ...)` (rate of histogram buckets)
  **before** applying `histogram_quantile()`; never call it on a single-
  pod/instance series.

## 7. Safety note: `histogram_quantile` aggregation

**Always aggregate the histogram buckets across replicas before computing
quantiles.** Wrong pattern (computes per-pod p99, then summarizes — wrong
for fleet): `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))`
— this returns one p99 per series; the series is per-pod, so the result is
per-pod p99, which has no operational meaning.

**Correct pattern** (used throughout `alert-rules.yml`):

```promql
histogram_quantile(
  0.99,
  sum by (le, service, route) (
    rate(http_request_duration_seconds_bucket[5m])
  )
)
```

The `sum by (le, ...)` step merges bucket counts across all replicas/series
that share the label set; `histogram_quantile()` then interpolates a real
fleet-wide p99. The current S2.7 alerts in `infra/observability/prometheus/
alert-rules.yml` follow this pattern; the note is here so future engineers
don't regress it.

## 8. Sign-off block

- [x] **PlatformArchitect** — SLO targets approved 2026-06-12; F1–F3 queued.
- [x] **SREEngineer** (me) — locked targets; per-bucket burn alerts in
  `alert-rules.yml`; per-bucket runbook stubs created; `histogram_quantile`
  safety note added.
- [ ] **FullstackEngineer** — surface the SLO targets in `/readyz` payload
  (optional, nice-to-have; not blocking).
- [ ] **SecurityArchitect** (S2.8 owner) — review per-bucket risk-calc SLOs
  against threat model; `xxlarge` may need a stricter target for security-
  critical SBOMs.

---

*End of SLO Targets — Security Stack v1.0 (Locked)*
