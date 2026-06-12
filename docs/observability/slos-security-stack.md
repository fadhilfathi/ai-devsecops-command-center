# SLO Targets — Sprint 2 Security Stack

> **Owner:** SREEngineer
> **Sprint:** 2 — Security Stack
> **Status:** **Locked v1.2** (PlatformArchitect round-1 sign-off 2026-06-12, round-2 sign-off 2026-06-12 with B1–B4 + C1–C3, round-3 sign-off 2026-06-12 with D1–D5 + §3.7 + §5.1.1, **round-6 closure 2026-06-12 with D7 5-bucket scheme + §3.11 gauge + §3.8 over-cap resolved by `tenant_id_hash` drop**; D6 `tenant_tier` addition still pending PlatformArchitect final verdict)
> **Last Updated:** 2026-06-12 (round 6 closure)
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

**Per-`sbom_size_bucket` SLOs (95% of calculations complete within the target; p99 is the 99th-percentile latency budget, ~2× of the 95% target).**

> **Round 6 (2026-06-12) — D7 5-bucket scheme LOCKED.** SecurityArchitect's D7 amendment replaces the round-5 5-bucket scheme with a cap-driven version. The `xxlarge` bucket is **dropped** (former ≥50k workloads now flow into `xlarge`), and a new `xs` bucket is **added** (sub-10-component SBOMs should be sub-100ms in steady state). Bucket thresholds:
> - **xs:** < 10 components
> - **small:** 10 – 99
> - **medium:** 100 – 999
> - **large:** 1,000 – 4,999
> - **xlarge:** ≥ 5,000 (absorbs former xxlarge overshoots)
>
> **Why the change (SecurityArchitect, S2.8 cap-driven):** the S2.8 cap on transitive-closure passes for the `full` algorithm makes ≥5k-component SBOMs the practical upper bound of the supported workload. A separate ≥50k bucket is operationally redundant (those SBOMs are now blocked upstream by the S2.8 cap) and would have created a dead alert path. The new `xs` bucket gives actionable signal on trivially-small SBOMs that should never exceed 100ms.

| `sbom_size_bucket` | Component range        | 95% SLO target | p99 latency budget | Rationale |
|---|---|---:|---:|---|
| `xs`               | < 10                   | 0.5 s | **1 s**     | Trivial; sub-100ms steady state. Cold-start budget: 0.5s. |
| `small`            | 10 – 99                | 1 s   | **2 s**     | Trivial graph traversal. |
| `medium`           | 100 – 999              | 5 s   | **10 s**    | Sub-second in practice; budget is for cold cache / GC. |
| `large`            | 1,000 – 4,999          | 15 s  | **30 s**    | Graph build + transitive risk propagation. |
| `xlarge`           | ≥ 5,000                | 60 s  | **120 s**   | Risk propagation O(V+E); p99 dominated by deep transitive chains. Absorbs former xxlarge overshoots; SLO overshoot is acceptable. |

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

**Per-bucket burn alerts (round 6, D7 5-bucket scheme):**
- `RiskCalcHighLatencyXs` — p95 of `xs` bucket > 0.5 s for 5 min (NEW; sub-10-component SBOMs)
- `RiskCalcHighLatencySmall` — p95 of `small` bucket > 1 s for 5 min
- `RiskCalcHighLatencyMedium` — p95 of `medium` bucket > 5 s for 5 min
- `RiskCalcHighLatencyLarge` — p95 of `large` bucket > 15 s for 5 min
- `RiskCalcHighLatencyXlarge` — p95 of `xlarge` bucket > 60 s for 5 min (absorbs former xxlarge)
- ~~`RiskCalcHighLatencyXxlarge`~~ — **RETIRED in round 6**; former xxlarge workloads now flow into `RiskCalcHighLatencyXlarge`. Runbook stub `docs/runbooks/RiskCalcHighLatencyXxlarge.md` is kept for reference but the alert is no longer emitted (the metric label `sbom_size_bucket="xxlarge"` is also dropped from emissions).

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

### 4.2 `devsecops_audit_log_emission_total` SLO (round 6 closure, ComplianceOfficer path (b))

> **Owner spec:** ComplianceOfficer (S2.9 owner, 2026-06-12)
> **Added:** 2026-06-12 (round 6 closure; not in original S2.7 hand-in)
> **Purpose:** close the observability gap for the S2.9 POA&M audit log
> emission. This SLO is an **integrity guardrail**, not a runtime SLI:
> audit emission failures mean security-relevant events are silently
> lost, which is a compliance regression (CIS 8.11, NIST AU-2/AU-3).

**Per-result 99% emission-success SLO:**

| `result` | Emission success rate target | Window | Page threshold |
|---|---|---|---|
| `success` | **99%** of all audit_log emissions (i.e. error rate ≤ 1%) | 30d | error rate > 1% over 5m |
| `error`   | (the inverse — should be ≤ 1%) | 30d | rate > 0.1/s for 5m → ticket; > 1/s for 5m → page |

**Why 99% (not 95%):** the 1% error budget is for genuine record-keep
failures (write contention, schema validation errors, bus-disconnected
edge cases), not for legitimate business rule violations. A 1% error
rate over 30d means **at most 1 audit record in 100 is silently lost**,
which is the upper bound of "acceptable" for compliance. Going below
99% (i.e. higher success rate) is a stretch goal but not required.

**Alert:** `AuditLogEmissionErrorRate` (added in `alert-rules.yml`
under the new `security_stack.audit_emission` group, severity **P2
(ticket) + page on >1/s for 5m**).

**Cardinality:** the metric is `audit_log_emission_total{service, result}`
with `result in {success, error}` = **2 series per service**. Compliance-
service emits ~22 series total (2 audit + ~20 default process metrics
with `compliance_service_` prefix). Well under the 50k cap.

**Runbook:** `docs/runbooks/compliance-audit-log.md` (ComplianceOfficer
to create; cross-link from the alert annotation).

**Why a separate group from §3.10 S2.8 controls:** audit emission is a
S2.9 deliverable, not S2.8. The `security_stack.audit_emission` group
keeps the alert routing and runbook cross-link clean. If Sprint 3
introduces audit emission from other services (security-service, agent-
service), the alert pattern generalizes — just add a new alert rule
with the same PromQL and a different `service` label.

## 5. SLO summary table

| Metric                                              | SLO (95% within) | Window  | Page threshold |
|-----------------------------------------------------|------------------|---------|----------------|
| `devsecops_sbom_generation_duration_seconds` (image) | 60 s            | 30d     | 14.4× burn, 1h & 6h |
| `devsecops_sbom_generation_duration_seconds` (repo)  | 120 s           | 30d     | 14.4× burn, 1h & 6h |
| `devsecops_sbom_generation_duration_seconds` (all)   | 60 s            | 30d     | 14.4× burn, 1h & 6h |
| `devsecops_risk_calculation_duration_seconds` (xs)     | 0.5 s          | 30d     | p95 > 0.5 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (small)  | 1 s            | 30d     | p95 > 1 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (medium) | 5 s            | 30d     | p95 > 5 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (large)  | 15 s           | 30d     | p95 > 15 s, 5m |
| `devsecops_risk_calculation_duration_seconds` (xlarge) | 60 s           | 30d     | p95 > 60 s, 5m |
| ~~`devsecops_risk_calculation_duration_seconds` (xxlarge)~~ | ~~300 s~~   | ~~30d~~ | ~~p95 > 300 s, 10m~~ RETIRED round 6 |
| `devsecops_eventbus_lag_seconds`                    | 5 s             | 30d     | p99 > 5 s, 10m |
| `devsecops_eventbus_lag_seconds` (critical)         | 30 s            | 30d     | p99 > 30 s, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (nvd)  | 7,200 s (2h)  | 30d     | p95 > 2h, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (ghsa) | 900 s (15m)  | 30d     | p95 > 15m, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (osv)  | 3,600 s (1h)  | 30d     | p95 > 1h, 5m |
| `devsecops_vulnerability_ingestion_lag_seconds` (all)   | 3,600 s (1h)  | 30d     | p95 > 1h, 5m |
| `devsecops_audit_log_emission_total{result="error"}`     | ≤ 1% of all emissions | 30d     | rate > 0.1/s for 5m (ticket), > 1/s for 5m (page) |

### 5.6 `devsecops_vulnerability_ingestion_lag_seconds` targets (B2)

> **Status:** targets locked provisionally on 2026-06-12 per
> PlatformArchitect sign-off; will be **re-confirmed at end of S2.11
> E2E validation** with the actual NVD/GHSA/OSV polling cadence and
> the first 30d of lag telemetry. **Polling cadence confirmed by
> VulnerabilityIntelligenceAgent on 2026-06-12 (round 6):** NVD=60min,
> GHSA=15min (webhook), OSV=30min, EPSS=6h, KEV=6h. The targets below
> are now anchored to a real cadence — GHSA has 60× headroom over
> polling (15min SLO vs 15min cadence), NVD has 2× headroom (2h SLO
> vs 60min cadence), and OSV has 2× headroom (1h SLO vs 30min cadence).
> If polling cadence changes in production, the SLOs move together.

**Per-source 95% lag SLOs (headroom-anchored):**

| Source  | Polling cadence | 95% SLO target | Headroom | p99 expected (informational) | Rationale |
|---------|----------------:|---------------:|---------:|----------------------------:|-----------|
| `nvd`   | 60 min          | **2 h** (7,200 s)   | 2×  | ~4 h                | NVD updates roughly every 2h; 95% of CVEs should land within one cycle. |
| `ghsa`  | 15 min (webhook)| **15 min** (900 s)  | 1×  | ~30 min             | GitHub Security Advisories are webhook-driven; near real-time. |
| `osv`   | 30 min          | **1 h** (3,600 s)   | 2×  | ~2 h                | OSV.dev API polling; depends on cadence. |
| `epss`  | 6 h             | (informational)     | —    | —                    | EPSS scores shift slowly; lag is not security-critical. |
| `kev`   | 6 h             | (informational)     | —    | —                    | CISA KEV catalog; lag is not security-critical. |
| **Aggregate** | —         | **1 h** (3,600 s) | —     | ~2 h                | 95% of all CVEs ingested within 1h of upstream publication. |

> **GHSA-headroom note (round 6):** GHSA's 15min SLO has 1× headroom
> over the 15min polling cadence, which is **tighter than NVD/OSV**.
> This is intentional: GHSA is the primary source for actively-exploited
> vulnerabilities (matches the S2.8 T-02 CVE feed integrity goal), and
> a delay is a security regression, not just a telemetry gap. If GHSA
> lag exceeds 15min consistently, **escalate immediately** — either
> the webhook is broken or the ingestion service is degraded.

**Why a histogram (not a gauge) for lag:** a gauge is point-in-time and
can be missed by scrapes; a histogram captures the *distribution* over
the scrape window and is the right primitive for `histogram_quantile()`
p95 math. Implementation: vuln-intel records one observation per CVE on
successful ingestion, with lag = `now - source.published_at`.

**Alternative staleness source (round 6):** the `VulnIngestionLag` alert
should use the new `devsecops_vuln_feed_last_refresh_timestamp_seconds`
gauge (`metrics-spec.md` §3.11) as the **primary staleness signal**, with
the histogram reserved for p95 distribution math. The gauge survives a
full vuln-intel restart; the histogram does not. Both metrics emitted
by `vulnerability-service` (port 4008).

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

**Round 6 sign-off (D6/D7/§3.8.4, SREEngineer 2026-06-12, full closure):**

- **D6 — `target_type` final values + `tenant_tier` addition** 🔒 LOCKED
  (partial). `target_type` final values: `image|filesystem|repo|archive|
  directory|sbom` (SecurityArchitect-confirmed). `tenant_tier` (free/pro/
  enterprise) added to `devsecops_sbom_generation_duration_seconds`,
  **pending PlatformArchitect final verdict on the ~230k per-service
  cardinality cost** (3× of D2's ~78k). Conditional acceptance from
  SecurityArchitect: Sprint 3 recording-rule pre-aggregation on
  `(target_type, result, ecosystem)` is acceptable mitigation if approved.
- **D7 — `sbom_size_bucket` 5-bucket scheme** 🔒 LOCKED. Replaces the
  round-5 scheme (small/medium/large/xlarge/xxlarge at 100/1k/10k/50k
  thresholds). New scheme: xs (<10) / small (10–99) / medium (100–999) /
  large (1k–4,999) / xlarge (≥5k). `xxlarge` dropped (former ≥50k workloads
  flow into `xlarge`; S2.8 cap blocks upstream SBOMs at ~10k so the ≥50k
  bucket would be dead). `xs` added for sub-10-component SBOMs that should
  be sub-100ms. SLO targets in §3 re-calibrated; per-bucket alerts in
  `alert-rules.yml` renamed (5 per-bucket alerts: Xs, Small, Medium,
  Large, Xlarge; Xxlarge alert retired). Runbook stubs updated; new
  `RiskCalcHighLatencyXs.md` stub created.
- **§3.8.4 merge** 🔒 LOCKED. The S2.8 §3.10.7
  `devsecops_rate_limit_rejections_total` metric (with `route` + `bucket`
  labels) is merged into §3.8.4 with the same name. §3.10.7 deleted.
  Per-route label retained (per SecurityArchitect amendment) for security
  forensics; cardinality impact negligible.
- **§3.8 cardinality over-cap** ✅ RESOLVED (2026-06-12, round 6).
  FullstackEngineer's `metrics.ts` helper LANDED, **with `tenant_id_hash`
  label DROPPED from all 6 proxy metrics**. Security-service :4003
  per-service total drops from ~109,400 to ~560 series (1,950× reduction,
  well under the 50k soft cap). Sprint 3 recording-rule pre-aggregation
  for §3.8 is **NO LONGER NEEDED** — removed from the Sprint 3 queue.
- **§3.11 `vuln_feed_last_refresh_timestamp_seconds`** 🔒 LOCKED. New
  gauge spec added to `metrics-spec.md` §3.11 (5 sources, trivial
  cardinality, owned by VulnerabilityIntelligenceAgent). Pending emission
  from `vulnerability-service` (port 4008). Will become the primary
  staleness signal for `VulnIngestionLag` alerts (S2.11 E2E validation).

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
- [x] **FullstackEngineer** — `metrics.ts` helper LANDED at
  `backend/common/observability/metrics.ts` (sets `service` label from
  `OTEL_SERVICE_NAME`). **Round 6:** `tenant_id_hash` label DROPPED from
  all 6 proxy metrics — this **resolves the §3.8 cardinality over-cap
  automatically** (security-service :4003 drops from ~109,400 to ~560
  series per-service, well under the 50k soft cap). **Sprint 3
  recording-rule pre-aggregation for §3.8 is NO LONGER NEEDED.** §3.8.4
  metric renamed to `devsecops_rate_limit_rejections_total` with `route` +
  `bucket` labels (D7 5-bucket scheme). 4 other Node services pending
  adoption. /readyz SLO payload is still optional (nice-to-have).
- [x] **SecurityArchitect** (S2.8 owner) — D6/D7/§3.8.4 verdicts confirmed
  2026-06-12 (round 6): D6 `target_type` final values LOCKED
  (`image|filesystem|repo|archive|directory|sbom`), D7 5-bucket
  `sbom_size_bucket` scheme LOCKED (xs/small/medium/large/xlarge, drop
  xxlarge, xs added), §3.8.4 merge LOCKED with `route` label retained.
  Per-bucket risk-calc SLOs in §3 are calibrated against the new scheme.
  **Conditional acceptance on D6 `tenant_tier` addition** — pending
  PlatformArchitect final verdict on the cost-benefit (~230k per-service
  vs current ~78k).
- [x] **VulnerabilityIntelligenceAgent** — polling cadence confirmed 2026-06-12
  (round 6): NVD=60min, GHSA=15min (webhook), OSV=30min, EPSS=6h, KEV=6h.
  SLO targets in §5.6 are now **anchored to the real cadence** (NVD/OSV
  have 2× headroom; GHSA has 1× headroom — intentional, security-driven).
  `vuln_feed_last_refresh_timestamp_seconds` gauge spec added to
  `metrics-spec.md` §3.11 — pending emission from `vulnerability-service`
  (port 4008). GHSA-headroom note added in §5.6.
- [x] **ComplianceOfficer (S2.9 owner) + SREEngineer (Sprint 2.5/2.11)** —
  ✅ **DONE 2026-06-12.** ComplianceOfficer shipped path (b) audit
  emission in compliance-service (4 files modified, 1 new `audit.ts` at
  `backend/services/compliance/src/observability/audit.ts`). Counter
  name: `audit_log_emission_total{service, result}` (2 series per
  service; 11 `AuditKind` values enumerated). SREEngineer added §4.2
  (99% emission-success SLO over 30d) and 2 alerts to
  `alert-rules.yml` (`AuditLogEmissionErrorRate` ticket at error rate
  >1% over 5m, `AuditLogEmissionErrorRatePage` page at error rate
  >1/s for 5m). 30 rules total, lint exit 0. Cardinality well under
  cap (~22 series for compliance-service). **Out of scope (next
  follow-up):** ComplianceOfficer to create
  `docs/runbooks/compliance-audit-log.md` (Sprint 2.5/2.11 task
  `019ebc0f-ab38` filed on team board). Tracked in `metrics-spec.md` §9
  as Sprint 2.5/2.11.
  deferred work.
- [ ] **Lead / S2.11 E2E validation owner** — confirm the SLOs are achievable
  in production over the 30d baseline; tune targets if real telemetry shows
  the p99 budgets are systematically missed (don't tighten on a single
  bad day; relax only if 4+ weeks of data shows consistent overshoot).
  Add the alert for `devsecops_vulnerability_ingestion_lag_seconds` to
  `alert-rules.yml` once the cadence is confirmed. **Add 4 alerts**
  (one per source + aggregate) to `security_stack.runtime` group.
- [ ] **SREEngineer (Sprint 3, D2 only)** — implement **recording-rule
  pre-aggregation** for `devsecops_sbom_generation_duration_seconds` to
  address the cardinality over-cap from D2 (per-service total ~78,000,
  over the 50,000 soft cap). Per PlatformArchitect 2026-06-12 ACK: default
  option 1, pre-aggregate on `(target_type, result)` for the alert path
  while keeping raw series for dashboards. Expected drop: 78k → ~25k
  active series per service. Switch the 9 S2.7 alerts to use the
  recording rule. Tracked in `infra/observability/prometheus/
  recording-rules.yml` (new file) and `docs/observability/metrics-spec.md`
  §3.1 callout.
- [ ] **SREEngineer (Sprint 3, §3.8) — NO LONGER NEEDED (round 6).**
  Recording-rule pre-aggregation for `devsecops_proxy_request_duration_seconds`
  was queued to address the §3.8 cardinality over-cap (security-service
  :4003 per-service total ~109,400 at N=50 × 4 replicas). **Resolved
  2026-06-12** by FullstackEngineer dropping `tenant_id_hash` from all
  6 proxy metrics in the LANDED `metrics.ts` helper. Per-service total
  is now ~560, **well under the 50k soft cap**. **REMOVED from Sprint 3
  queue** — replaced by the (much smaller) D2 work.

---

*End of SLO Targets — Security Stack v1.2 (Locked)*
