# SLO Targets — Sprint 2 Security Stack

> **Owner:** SREEngineer
> **Sprint:** 2 — Security Stack
> **Status:** **Locked v1.2** (PlatformArchitect round-1 sign-off 2026-06-12, round-2 sign-off 2026-06-12 with B1–B4 + C1–C3, round-3 sign-off 2026-06-12 with D1–D5 + §3.7 + §5.1.1)
> **Last Updated:** 2026-06-12 (post round-3 sign-off)
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

## 2. `devsecops_sbom_generation_duration_seconds` SLO targets

**Per-`target_type` SLOs (95% of generations complete within the target):**

| `target_type` | 95% SLO target | p99 expected (informational) | Rationale |
|---|---|---:|---|
| `image`       | 60 s   | ~120 s  | Image scans pull layers + do package detection; most are < 30s, p99 dominated by large/distroless images. |
| `filesystem`  | 30 s   | ~60 s   | Local FS walk; fast path. |
| `directory`   | 30 s   | ~60 s   | Same as `filesystem`; aliased for clarity. |
| `archive`     | 60 s   | ~120 s  | tar/zip extract + parse; can be slow on large archives. |
| `repo`        | 120 s  | ~240 s  | git clone + parse; network-bound. Worst case for SBOM gen. |

**Aggregate SLO:** 95% of all generations, regardless of `target_type`, complete
within **60 s** (the most common target). 99% within **180 s** (safety net for repos).

**Burn alerts (derived from this SLO):**
- **Fast burn (page):** 14.4× burn over 1h AND 6h windows.
- **Slow burn (ticket):** 1× burn over 24h AND 3d windows.

**Calibration note:** the existing `ScanQueueBacklog` alert (depth > 100, 15m)
catches capacity problems; these new p99 alerts catch *per-request* performance
regressions that may not surface as a backlog for several hours.

## 3. `devsecops_risk_calculation_duration_seconds` SLO targets

**Per-`sbom_size_bucket` SLOs (95% of calculations complete within the target; p99 is the 99th-percentile latency budget, ~2× of the 95% target):**

| `sbom_size_bucket` | Component range        | 95% SLO target | p99 latency budget | Rationale |
|---|---|---:|---:|---|
| `small`            | < 100                  | 1 s   | **2 s**    | Trivial graph traversal. |
| `medium`           | 100 – 999              | 5 s   | **10 s**   | Sub-second in practice; budget is for cold cache / GC. |
| `large`            | 1,000 – 9,999          | 15 s  | **30 s**   | Graph build + transitive risk propagation. |
| `xlarge`           | 10,000 – 49,999        | 60 s  | **120 s**  | Risk propagation O(V+E); p99 dominated by deep transitive chains. |
| `xxlarge`          | ≥ 50,000               | 300 s | **600 s**  | Full OS images and monorepos; 5–10× slower than `xlarge` per PlatformArchitect. |

> **Callout — `full` algorithm budget:** the SLOs above are calibrated
> against the `cvss_epss` algorithm. Teams running `full` for
> security-critical SBOMs should expect to **overshoot** these targets
> (full runs a graph-closure pass; expect 2–5× the `cvss_only` baseline).
> Provision accordingly: more replicas, or schedule `full` runs off-peak.
> On-call should not page on `full` overshoots unless the 99p exceeds the
> budget by 3×.

**Per-`algorithm` notes (lower-effort algorithms, for context):**
- `cvss_only` is the fastest (no external lookups).
- `cvss_epss` adds a Redis lookup; expect +50–200 ms over `cvss_only`.
- `cvss_epss_kev` adds a CISA KEV catalog lookup; expect +100–500 ms over `cvss_only`.

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

## 4. `devsecops_eventbus_lag_seconds` p99 target (CONFIRMED)

**Target (SLO contract):** **5 s p99** (PlatformArchitect's proposal — **confirmed by SREEngineer**).

| Threshold | Action |
|---|---|
| p99 lag < 5 s  for 10 min | OK (within SLO) |
| p99 lag ≥ 5 s  for 10 min | **Page** (fast burn: SLO breached) |
| p99 lag ≥ 30 s for 5 min  | **Critical page** (3× over SLO; consumers falling badly behind) |
| p99 lag ≥ 60 s for 5 min  | **Page on-call lead** (4× over SLO; pipeline stalled) |

**Per-`stream` SLOs:**
- `security.events` — p99 < 5 s (critical security events must propagate fast)
- `compliance.events` — p99 < 30 s (compliance is not real-time critical)
- `audit.events` — p99 < 60 s (audit is asynchronous; high lag is acceptable for volume reasons)

**Aggregate platform SLI:** p99 lag across all streams < 5 s. Computed as
`histogram_quantile(0.99, sum(rate(devsecops_eventbus_lag_seconds_bucket[5m])) by (le))`.

### 4.1 Steady-state expectations (informational; NOT in SLO contract)

These are the **expected operating ranges** in a healthy cluster, used
for capacity planning and "is the system healthy" dashboards. They are
deliberately tighter than the SLO contract to give 2–5× headroom:

| Percentile | Steady-state target | SLO contract | Headroom |
|---:|---:|---:|---:|
| p50 (median) | **0.25 s** | — (not in SLO) | — |
| p99 | **1 s** | **5 s** | 5× headroom to SLO |

- **0.25s p50** is achievable for a healthy Redis Streams + small consumer
  group with no contention.
- **1s p99** gives 5× headroom from steady-state to SLO; 2× headroom to
  the 5s p99 SLO alert threshold.
- If steady-state p50 exceeds 0.5s or p99 exceeds 2s for >1h, file a
  capacity ticket — the SLO is intact, but the system is drifting.

> ⚠️ These targets are **informational**. They do not page. The SLO
> contract is the 5s p99 above. Do not add alerts on the steady-state
> thresholds; doing so creates alert noise and breaks the burn-rate
> SLO model.

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
| `devsecops_vulnerability_ingestion_lag_seconds` (nvd)  | 7,200 s (2h)  | 30d     | p95 > 2h, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (ghsa) | 900 s (15m)  | 30d     | p95 > 15m, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (osv)  | 3,600 s (1h)  | 30d     | p95 > 1h, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (all)   | 3,600 s (1h)  | 30d     | p95 > 1h, 5m |

### 5.6 `devsecops_vulnerability_ingestion_lag_seconds` targets (B2)

> **Status:** targets locked provisionally on 2026-06-12 per
> PlatformArchitect sign-off; will be **re-confirmed at end of S2.11
> E2E validation** with the actual NVD/GHSA/OSV polling cadence and
> the first 30d of lag telemetry. The VulnerabilityIntelligenceAgent
> has not yet confirmed the polling cadence; the targets below assume
> ~30min NVD/OSV polling and GHSA webhook delivery (PlatformArchitect's
> assumption). If polling is materially different, the targets move
> together.

**Per-source 95% lag SLOs:**

| Source  | 95% SLO target | p99 expected (informational) | Rationale |
|---------|---------------:|----------------------------:|-----------|
| `nvd`   | **2 h** (7,200 s)   | ~4 h                | NVD updates roughly every 2h; 95% of CVEs should land within one cycle. If polling is faster, the SLO can be tightened in S2.11. |
| `ghsa`  | **15 min** (900 s)  | ~30 min             | GitHub Security Advisories are webhook-driven; near real-time. |
| `osv`   | **1 h** (3,600 s)   | ~2 h                | OSV.dev API polling; depends on cadence. |
| **Aggregate** | **1 h** (3,600 s) | ~2 h             | 95% of all CVEs ingested within 1h of upstream publication. |

**Why a histogram (not a gauge) for lag:** a gauge is point-in-time and
can be missed by scrapes; a histogram captures the *distribution* over
the scrape window and is the right primitive for `histogram_quantile()`
p95 math. Implementation: vuln-intel records one observation per CVE on
successful ingestion, with lag = `now - source.published_at`.

**Action item for S2.11 E2E validation owner:** add the alert rule
(`VulnIngestionLagNVD` / `VulnIngestionLagGHSA` / `VulnIngestionLagOSV`
/ `VulnIngestionLagAggregate`) to `infra/observability/prometheus/
alert-rules.yml` once the polling cadence is confirmed and the SLOs
are re-validated.

### 5.7 S2.8 security-control SLOs (T-02, T-03, T-04, T-05, T-08, T-09)

> **Owner spec:** SecurityArchitect (S2.8 owner, 2026-06-12)
> **Added:** 2026-06-12 (S2.8 follow-up; not in original S2.7 hand-in)
> **Purpose:** close the observability gap for the S2.8 security
> controls. These SLOs are **integrity / tamper / cost guardrails**,
> not runtime SLI. They page on violations of "MUST be" invariants
> (e.g. audit chain MUST always verify) and ticket on cost/perf
> regression.

**Per-control SLOs:**

| Control | Metric | SLO target | Severity | Alert |
|---|---|---|---|---|
| **T-05** (tamper detection) | `devsecops_risk_score_audit_chain_verified{ok=1}` | **MUST equal fleet service count** (i.e. `ok=0` count MUST be 0) | P0 (page) | `RiskScoreAuditChainBroken` — `sum by (service)(...{ok="0"}) > 0` for 1m |
| **T-09** (data-exfil canary) | `devsecops_canary_test_failures_total` | **MUST stay 0** (any increment is a signal) | P0 (page) | `CanaryTestFailure` — `increase(...[1m]) > 0` for 1m |
| **T-02** (CVE feed integrity) | `devsecops_cve_feed_records_rejected_total{reason="integrity"}` | rejection rate < 0.1/s per feed over 5m | P2 (ticket) | `CveFeedIntegrityRejected` — `sum by (feed)(rate(...[5m])) > 0.1` for 5m |
| **T-04** (supply-chain verify) | `devsecops_cosign_verify_duration_seconds{result="success"}` | p95 < 30s over 5m | P3 (ticket) | `CosignVerifySlow` — `histogram_quantile(0.95, ...) > 30` for 10m |
| **T-08** (input validation) | `devsecops_sbom_validation_errors_total` / `devsecops_proxy_request_total` | ratio < 1% over 5m (i.e. 99% of requests pass validation) | P3 (ticket) | `SbomValidationErrorRate` — `sum(rate(errors)) / sum(rate(requests)) > 0.01` for 5m |
| **T-03** (LLM cost guardrail) | `devsecops_llm_token_budget_remaining` | gauge ≥ 20% (i.e. budget is 80% consumed) | P3 (ticket) | `LlmTokenBudgetLow` — gauge < 0.20 for 5m |

**SLO summary table update (extending §5):**

| Metric | SLO (95% within) | Window | Page threshold |
|---|---|---|---|
| `devsecops_sbom_validation_errors_total` / total | < 1% | 30d | ratio > 1% over 5m |
| `devsecops_cosign_verify_duration_seconds` (success) | 30s p95 | 30d | p95 > 30s, 10m |
| `devsecops_cve_feed_records_rejected_total` (integrity) | < 0.1/s per feed | 30d | rate > 0.1/s, 5m |
| `devsecops_risk_score_audit_chain_verified{ok=0}` | 0 (MUST equal fleet) | 30d | > 0, 1m |
| `devsecops_canary_test_failures_total` | 0 (MUST be 0) | 30d | increment > 0, 1m |
| `devsecops_llm_token_budget_remaining` | ≥ 20% | 30d | < 20%, 5m |

**Naming status:** provisionally added to `metrics-spec.md` §3.10 and
`alert-rules.yml` `security_stack.s2_8_controls` group (2026-06-12).
**D6 + D7 + §3.8.4 merge verdicts pending PlatformArchitect** —
final lock when those resolve.

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

**3 follow-up items (F1–F3), all addressed in this turn:**

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

**Round 2 sign-off (B1–B4 + C1–C3), PlatformArchitect 2026-06-12:**

- **B1 — 99p per-bucket risk-calc targets** ✅ APPROVED. Values: small=2s,
  medium=10s, large=30s, xlarge=120s, xxlarge=600s (2× of 95p). Added to
  §3 table.
- **B2 — New metric `devsecops_vulnerability_ingestion_lag_seconds`** ✅
  APPROVED with provisional targets (NVD=2h, GHSA=15m, OSV=1h, aggregate=1h).
  Targets assume ~30min polling cadence; **pending VulnerabilityIntelligenceAgent
  confirmation**. See §5.6 for full table; alert to be added in S2.11.
- **B3 — SBOM-gen `xxlarge` bucket** ✅ APPROVED (option a, reject).
  The `xxlarge` bucket exists only on `risk_calculation_duration_seconds`
  per the locked spec; SBOM gen is not sliced by size.
- **B4 — Steady-state informational targets** ✅ APPROVED. p50=0.25s,
  p99=1s, 5× headroom to 5s SLO. Added as §4.1, marked "informational;
  NOT in SLO contract" with explicit "do not add alerts" warning.
- **C1 — Column-header confusion** ✅ fixed in §2 and §3.
- **C2 — `full` algorithm overshoot** ✅ promoted to callout block in §3.
- **C3 — Sign-off checklist rows** ✅ added (S2.11 E2E validation +
  VulnerabilityIntelligenceAgent cadence + alert add).

**Round 3 sign-off (D1–D5 + §3.7 + §5.1.1), PlatformArchitect 2026-06-12:**

- **D1 — `sbom_size_bucket` 5-bucket scheme** 🔒 LOCKED. Pushed back on
  GitOpsManager's (xs/s/m/l/xl) and SBOMPipelineAgent's (4-bucket)
  alternatives. SLOs and per-bucket runbooks calibrated against the
  5-bucket scheme.
- **D2 — `target_type` vs `repo_shape`** ✅ SEPARATE LABELS.
  `target_type` keeps PlatformArchitect's 5 values (image/filesystem/
  repo/archive/directory); a NEW label `repo_shape ∈ {monorepo, service,
  package}` added to `devsecops_sbom_generation_duration_seconds`,
  populated only when `target_type="repo"` (empty string for others).
  Cardinality: +3. Pushed GitOpsManager to use `repo_shape`.
- **D3 — `format` label on sbom_gen** ⏸️ DEFERRED to Sprint 3. 4× cardinality
  jump (17,920 → ~72,000) is too close to the 50k soft cap. Pushed
  SBOMPipelineAgent to defer.
- **D4 — `result` label 4-value set** 🔒 LOCKED (`success, failure, timeout,
  cancelled`). Pushed GitOpsManager to align; `cancelled` is the "users
  rage-quitting" signal distinct from `failure`.
- **D5 — `severity` label 5-value set** 🔒 LOCKED (`critical, high, medium,
  low, unknown`). Pushed GitOpsManager to align; `unknown` is the early
  signal for partial feed population.

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
  Round 2 sign-off (B1 99p per-bucket, B2 VulnIngestionLag new metric,
  B3 SBOM-gen xxlarge rejected, B4 steady-state 0.25s p50 / 1s p99, C1–C3
  doc fixes) — all accepted 2026-06-12. Round 3 sign-off (D1–D5
  divergences + Q3 Node.js service-label gap + §3.7 VulnIngestionLag
  metric + §5.1.1 Node.js helper footnote) — all accepted 2026-06-12.
- [x] **SREEngineer** (me) — locked targets; per-bucket burn alerts in
  `alert-rules.yml`; per-bucket runbook stubs created; `histogram_quantile`
  safety note added; §2/§3 column headers fixed; B4 steady-state
  sub-section added; C2 `full` algorithm callout promoted; B1 99p
  per-bucket table updated; D1–D5 resolved with redirect messages to
  GitOpsManager and SBOMPipelineAgent; §3.7 VulnIngestionLag metric
  added to metrics-spec.md; §5.6 VulnIngestionLag SLO targets added
  (provisional, S2.11 re-validation queued); §5.1.1 Node.js helper
  footnote added; `repo_shape` label added to spec §3.1.
- [ ] **FullstackEngineer** — surface the SLO targets in `/readyz` payload
  (optional, nice-to-have; not blocking). **Add `metrics.ts` helper**
  at `backend/common/observability/metrics.ts` (sets `service` label
  from `OTEL_SERVICE_NAME`); flag routed in this turn.
- [ ] **SecurityArchitect** (S2.8 owner) — review per-bucket risk-calc SLOs
  against threat model; `xxlarge` may need a stricter target for security-
  critical SBOMs.
- [ ] **VulnerabilityIntelligenceAgent** — confirm polling cadence (NVD/GHSA/OSV)
  so the `devsecops_vulnerability_ingestion_lag_seconds` SLO targets can be
  re-validated against real telemetry. Currently NVD=2h, GHSA=15min, OSV=1h
  **provisional** (assumes ~30min polling); targets move together when
  cadence is confirmed. **Also emit `vuln_feed_last_refresh_timestamp_seconds`
  gauge** (Lead-forwarded, non-blocking for S2.7).
- [ ] **ComplianceOfficer (S2.9 owner) + SREEngineer (Sprint 2.5/2.11)** —
  ComplianceOfficer to emit `audit_log_emission_total{service=
  "compliance-service", result}` from `poam.service.ts` and
  `evidence-attacher.ts` via `prom-client` (path (b) per SREEngineer
  2026-06-12 review). SREEngineer to add §4.2 "Audit log emission SLO"
  to this SLO doc (target: 95% of emissions succeed, i.e. `result="error"`
  rate ≤ 0.1 over 5m) and an `AuditLogEmissionErrorRate` alert to
  `alert-rules.yml`. Tracked in `metrics-spec.md` §9 as Sprint 2.5/2.11
  deferred work.
- [ ] **Lead / S2.11 E2E validation owner** — confirm the SLOs are achievable
  in production over the 30d baseline; tune targets if real telemetry shows
  the p99 budgets are systematically missed (don't tighten on a single
  bad day; relax only if 4+ weeks of data shows consistent overshoot).
  Add the alert for `devsecops_vulnerability_ingestion_lag_seconds` to
  `alert-rules.yml` once the cadence is confirmed. **Add 4 alerts**
  (one per source + aggregate) to `security_stack.runtime` group.
- [ ] **SREEngineer (Sprint 3)** — implement **recording-rule pre-aggregation**
  for `devsecops_sbom_generation_duration_seconds` to address the
  cardinality over-cap from D2 (per-service total ~78,000, over the
  50,000 soft cap). Per PlatformArchitect 2026-06-12 ACK: default option
  1, pre-aggregate on `(target_type, result)` for the alert path while
  keeping raw series for dashboards. Expected drop: 78k → ~25k active
  series per service. Switch the 9 S2.7 alerts to use the recording
  rule. Tracked in `infra/observability/prometheus/recording-rules.yml`
  (new file) and `docs/observability/metrics-spec.md` §3.1 callout.
- [ ] **SREEngineer (Sprint 3, second pass)** — implement **recording-rule
  pre-aggregation** for `devsecops_proxy_request_duration_seconds` to
  address the cardinality over-cap from §3.8 (security-service :4003
  per-service total ~109,400 at N=50 × 4 replicas, over the 50k soft
  cap). Same fix pattern as D2: pre-aggregate on `(route, target_service,
  result)` for the alert path while keeping raw series with
  `tenant_id_hash` for dashboards. Expected drop: 109k → ~25k per-service.
  Same `infra/observability/prometheus/recording-rules.yml` file, second
  rule group. Tracked in `docs/observability/metrics-spec.md` §3.8
  callout. **Both recording rules can be implemented in a single Sprint
  3 PR (~1-2 days of work).**

---

*End of SLO Targets — Security Stack v1.2 (Locked)*
