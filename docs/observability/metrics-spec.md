# Metrics Specification — Security Stack & Platform SLI

> **Project:** AI-DevSecOps Command Center
> **Document Owner:** Platform Architect (spec); SRE Engineer (ingestion, alerts)
> **Version:** 1.0.4 (Sprint 2, S2.7 + S2.8 hand-in) — **LOCKED 2026-06-12**
> **Last Updated:** 2026-06-12 (round 6: D7 5-bucket scheme applied to §3.3 + alert rules; §3.8 `tenant_id_hash` dropped (FullstackEngineer LANDED, resolves ~109k → ~560 cardinality over-cap); §3.10.7 deleted (merged into §3.8.4 rename); §3.11 vuln_feed gauge added; D6 still pending PlatformArchitect verdict)
> **Status:** **Locked** (PlatformArchitect sign-off 2026-06-12, rounds 1+2+3+5 closed end-to-end)
> **Companion:** `docs/observability/slos-security-stack.md` (SRE-owned, v1.2 Locked)
> **Cross-linked from:** `docs/architecture/event-bus.md` §14 (PlatformArchitect)

---

## 1. Purpose

This document is the **authoritative specification of the application-level
Prometheus metrics** emitted by the security stack and the platform event
bus. It locks:

- Metric **names, types, and label sets** (the *what*).
- Histogram **bucket schemes** (the *resolution*).
- **Naming, label, and cardinality conventions** (the *rules*).

It does **not** define SLOs, alert rules, or runbooks. Those live in
`slos-security-stack.md` (SRE-owned). The two docs cross-link.

## 2. Scope

| In scope | Out of scope |
|---|---|
| Security stack: `sbom-pipeline`, `vuln-intel`, `dependency-intel` | Other Sprint 3+ services (added per-PR) |
| Platform event bus SLI | Node-runtime metrics (GC, event loop) — use OTel defaults |
| Application-level histograms, counters, gauges | Tracing spans (OTel) |
| Cross-cutting naming & cardinality rules | SLOs / alerts / runbooks (`slos-security-stack.md`) |

## 3. Metric Catalogue

### 3.1 `devsecops_sbom_generation_duration_seconds`
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Owner service** | `sbom-pipeline` (port 4007) |
| **Purpose** | End-to-end SBOM generation latency |
| **Labels** | `service`, `source_type`, `ecosystem`, `target_type`, `result`, `repo_shape`, `tenant_tier` |
| **Allowed `source_type`** | `syft`, `dependency_track`, `import`, `manual` |
| **Allowed `ecosystem`** | `npm`, `pypi`, `maven`, `nuget`, `go`, `cargo`, `rubygems`, `composer`, `conan`, `apk`, `deb`, `rpm`, `generic`, `unknown` |
| **Allowed `target_type`** | `image`, `filesystem`, `repo`, `archive`, `directory`, `sbom` (D6) |
| **Allowed `result`** | `success`, `failure`, `timeout`, `cancelled` |
| **Allowed `repo_shape`** | `monorepo`, `service`, `package` (D2 — applies only when `target_type="repo"`; emit empty string for other `target_type` values, or use a `_unspecified` value to keep the label present) |
| **Allowed `tenant_tier`** | `free`, `pro`, `enterprise` (D6 — **pending PlatformArchitect verdict**; cardinality impact tracked in §7) |
| **Histogram buckets (seconds)** | Default Prometheus: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600` |
| **Cardinality (with D2 only, pre-D6)** | 1 service × 4 × 15 × 5 × 4 × 4 = **4,800 label combinations** × 16 buckets ≈ **76,800 time series** |
| **Cardinality (with D2 + D6, if approved)** | 4,800 × 3 = **14,400 label combinations** × 16 buckets ≈ **230,400 time series** (see §7) |

> ⚠️ **Cardinality impact of D2 (added `repo_shape`):** +3 label values →
> series count rises from 17,920 to **~76,800** (4× more). This pushes
> the per-service total above the 50,000 soft cap. The SLO alerts in
> `alert-rules.yml` filter on the most common label combos and do not
> explode. **Recommended: accept the +58k series for this metric, and
> the per-service total becomes ~78,000 (which is still operationally
> fine but warrants a note).** Long-term, evaluate Prometheus sharding
> or relabeling at end of Sprint 3 with real telemetry.
>
> **Mitigation queued for Sprint 3 (PlatformArchitect 2026-06-12):**
> recording-rule pre-aggregation on `(target_type, result)` will
> collapse the alert-rule path to ~25k series while keeping the raw
> series for dashboards. Tracked as a Sprint 3 follow-up item in the
> SLO doc §8 sign-off checklist and the metrics-spec.md §9 follow-up
> list. Default option for Sprint 3: option 1 (recording-rule
> pre-aggregation).

**Explicitly NOT included** (with rationale):
- `format` (e.g. `spdx-json`, `cyclonedx-json`) — defer to Sprint 3; derivable from the SBOM record; saves ~4× cardinality.
- `sbom_size_bucket` — risk calc owns this dimension; generation time correlates with size but the size info is in the SBOM record.
- `tenant_id` — **NEVER on a metric.** Cardinality bomb (one series per tenant) and a PII risk.
- `agent_id` / `worker_id` — internal dimensions; aggregate over workers.
- `request_id` — use logs/traces, not metrics.

### 3.2 `devsecops_vulnerability_ingestion_total`
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Owner service** | `vuln-intel` (port 4008) |
| **Purpose** | CVE records ingested from external feeds |
| **Labels** | `service`, `source`, `severity` |
| **Allowed `source`** | `nvd`, `ghsa`, `osv` |
| **Allowed `severity`** | `critical`, `high`, `medium`, `low`, `unknown` |
| **Cardinality** | 1 × 3 × 5 = **15 time series** |

### 3.3 `devsecops_risk_calculation_duration_seconds`
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Owner service** | `dependency-intel` (port 4009) |
| **Purpose** | Risk propagation algorithm latency per SBOM |
| **Labels** | `service`, `sbom_size_bucket`, `algorithm`, `result` |
| **Allowed `sbom_size_bucket`** | `xs` (<10), `small` (10–99), `medium` (100–999), `large` (1,000–4,999), `xlarge` (≥5,000) (D7 — SecurityArchitect, S2.8 cap-driven) |
| **Allowed `algorithm`** | `cvss_only`, `cvss_epss`, `cvss_epss_kev`, `full` |
| **Allowed `result`** | `success`, `failure`, `timeout`, `cancelled` |
| **Histogram buckets (seconds)** | `0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200` |
| **Cardinality** | 1 × 5 × 4 × 4 = **80 label combinations** × 14 buckets ≈ **1,120 time series** |

**Why 5 size buckets (D7, S2.8 cap-driven):** the original 5-bucket scheme (small/medium/large/xlarge/xxlarge at 100/1k/10k/50k thresholds) was adequate for raw risk-propagation latency, but S2.8 introduced a **capped transitive-closure pass** for the `full` algorithm on security-critical SBOMs. The new scheme **drops `xxlarge`** (≥50k components) and **splits the bottom into `xs`** (<10 components) for trivially small SBOMs that should be sub-100ms in steady state. The thresholds tighten the "tail" of the distribution (xlarge now starts at 5k, not 10k) so that the SLO budgets in `slos-security-stack.md` §3 stay proportional. **xxlarge workload is routed to the `xlarge` bucket** (no separate label), accepting that very large SBOMs overshoot the SLO and are tracked via the per-bucket `RiskCalcHighLatencyXlarge` alert.

### 3.4 `devsecops_active_scans`
| Attribute | Value |
|---|---|
| **Type** | Gauge |
| **Owner service** | `sbom-pipeline` |
| **Purpose** | Currently in-flight scans |
| **Labels** | `service`, `scanner_type` |
| **Allowed `scanner_type`** | `syft`, `dependency_track`, `trivy`, `grype` |
| **Cardinality** | 1 × 4 = **4 time series** |

### 3.5 `devsecops_queue_depth`
| Attribute | Value |
|---|---|
| **Type** | Gauge |
| **Owner service** | each service for its own queue |
| **Purpose** | Pending work items in the service's queue |
| **Labels** | `service`, `queue_name` |
| **Cardinality** | ≤ **5–10 time series per service** (one per queue) |

### 3.6 `devsecops_eventbus_lag_seconds` (PLATFORM SLI)
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Owner** | **Every service emits; PlatformArchitect owns the SLO definition** |
| **Purpose** | Time between event publish and consumer ack — the platform's main reliability contract |
| **Labels** | `stream`, `consumer_group`, `subject` |
| **Histogram buckets (seconds, SLO-shaped)** | `0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300` |
| **Cardinality budget** | streams × groups × subjects ≤ **~5,000 time series** (cluster-wide) |

**SLO (see `slos-security-stack.md` for full table):**
- Aggregate: 5s p99
- `{stream="security.events"}`: 5s p99 (critical path)
- `{stream="compliance.events"}`: 30s p99
- `{stream="audit.events"}`: 60s p99

**Why a histogram (not a gauge) for lag:** a gauge is point-in-time and can be missed by scrapes; a histogram captures the *distribution* over the scrape window and is the right primitive for `histogram_quantile()` p99 math.

### 3.7 `devsecops_vulnerability_ingestion_lag_seconds` (B2)
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Owner service** | `vuln-intel` (port 4008) |
| **Purpose** | Time from upstream CVE publication to local ingestion — the freshness SLI for the vulnerability feed |
| **Labels** | `service`, `source` |
| **Allowed `source`** | `nvd`, `ghsa`, `osv` |
| **Histogram buckets (seconds, SLO-shaped)** | `5, 15, 30, 60, 120, 300, 600, 1800, 3600` (5 s … 1 h) |
| **Cardinality** | 1 × 3 = **3 label combinations** × 9 buckets = **27 time series** |

**SLO targets (95% of CVEs ingested within the target; see `slos-security-stack.md` §5.6 for full table):**

| Source  | 95% SLO target | Rationale |
|---------|---------------:|-----------|
| `nvd`   | **2 h** (7,200 s)   | NVD updates roughly every 2h; 95% should land within one cycle. |
| `ghsa`  | **15 min** (900 s)  | GitHub Security Advisories are webhook-driven; near real-time. |
| `osv`   | **1 h** (3,600 s)   | OSV.dev API polling; depends on cadence. |
| **Aggregate** | **1 h** (3,600 s) | 95% of all CVEs ingested within 1h of upstream publication. |

> **Status:** targets locked provisionally on 2026-06-12 per
> PlatformArchitect sign-off, **pending VulnerabilityIntelligenceAgent
> confirmation of the actual polling cadence**. If polling is materially
> different from ~30min (NVD/OSV) or webhook (GHSA), the targets move
> together. Re-validate at end of S2.11 E2E validation.

**Why a histogram (not a gauge) for lag:** same rationale as §3.6 — a
gauge is point-in-time and can be missed by scrapes; a histogram
captures the *distribution* of ingestion latencies over the scrape
window and is the right primitive for `histogram_quantile()`.

**Implementation note:** vuln-intel records an observation per CVE on
successful ingestion, with lag = `now - source.published_at`. Lag is
reset (not cumulative) — the histogram captures the *distribution* of
ingestion latencies over the scrape window.

### 3.8 Security-service proxy-layer metrics (FullstackEngineer S2.7 follow-up)

> **Owner service:** `security-service` (port 4003, Node.js / Fastify)
> **Owner:** FullstackEngineer
> **Added:** 2026-06-12 (S2.7 SLO follow-up; not in original S2.7 hand-in)
> **Purpose:** close the observability gap between the public API
> (security-service :4003) and the 3 Python services (sbom-pipeline,
> vuln-intel, dependency-intel). Without these metrics, the entire
> ingress layer is a black box.

#### 3.8.1 `devsecops_proxy_request_duration_seconds`
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Purpose** | Latency of the security-service → Python service proxy hop |
| **Labels** | `route`, `target_service`, `result`, `tenant_id_hash` |
| **Allowed `route`** | `/sbom/generate`, `/sbom/analyze`, `/vulnerabilities/ingest`, `/risk/calculate`, `/security/dashboard` |
| **Allowed `target_service`** | `sbom-pipeline`, `vuln-intel`, `dependency-intel` |
| **Allowed `result`** | `success`, `failure`, `timeout`, `cancelled` |
| **Histogram buckets (seconds)** | `0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600` (12 buckets) |
| **Cardinality (per replica)** | 5 routes × 3 targets × 4 results × N_tenants × 12 buckets = 720 × N_tenants |
| **Cardinality (4 replicas × N=50)** | **72,000 series** (74% of per-service total) |

**Why `tenant_id_hash`:** the per-tenant 99p SLO is the most useful
slice for the S2.11 E2E validation (different tenants have wildly
different SBOM sizes; per-tenant 99p surfaces tenant-specific issues
that fleet-wide 99p masks). Hash, not raw, to keep cardinality bounded
and PII-safe. Salt configured from `METRICS_TENANT_SALT` env var.

#### 3.8.2 `devsecops_proxy_request_total`
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Purpose** | All proxy calls (success + 4xx + 5xx) |
| **Labels** | `route`, `target_service`, `status_code`, `tenant_id_hash` |
| **Allowed `status_code`** | `200`, `400`, `401`, `403`, `404`, `429`, `500`, `502`, `503`, `504` (10 values) |
| **Cardinality (per replica, N=50)** | 5 × 3 × 10 × 50 = 7,500 series |

#### 3.8.3 `devsecops_eventbus_publish_total`
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Purpose** | security-service → event bus publish (SBOM_TOPIC, VULN_TOPIC, RISK_TOPIC) |
| **Labels** | `topic`, `result` |
| **Allowed `topic`** | `SBOM_TOPIC`, `VULN_TOPIC`, `RISK_TOPIC` |
| **Allowed `result`** | `success`, `dropped`, `error` |
| **Cardinality** | 3 × 3 = **9 series** (trivial) |

#### 3.8.4 `devsecops_rate_limit_triggered_total`
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Purpose** | Per-route 429 trigger count (10 req/s limit) |
| **Labels** | `route`, `tenant_id_hash` |
| **Cardinality (per replica, N=50)** | 5 × 50 = 250 series |

#### 3.8.5 `devsecops_auth_failure_total`
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Purpose** | Per-route auth failure breakdown |
| **Labels** | `route`, `reason`, `tenant_id_hash` |
| **Allowed `reason`** | `missing_token`, `invalid_signature`, `expired`, `tenant_mismatch` |
| **Cardinality (per replica, N=50)** | 5 × 4 × 50 = 1,000 series |

#### 3.8.6 `devsecops_dashboard_query_duration_seconds`
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Purpose** | GET /security/dashboard aggregation latency |
| **Labels** | `endpoint`, `tenant_id_hash` |
| **Histogram buckets (seconds)** | `0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600` (12 buckets) |
| **Cardinality (per replica, N=50)** | 1 × 50 × 12 = 600 series |

> ⚠️ **Cardinality impact of §3.8:** at Sprint 2 expected N=50 tenants
> with 4 replicas, security-service :4003 emits **~97,400 active
> series**, which is **~2× the 50,000 per-service soft cap**. The
> dominant contributor is `devsecops_proxy_request_duration_seconds` at
> 72,000 (74%). This is the same pattern as D2 (`repo_shape` on
> sbom_gen): high-cardinality label on a histogram multiplies by
> N_tenants × N_buckets.
>
> **Mitigation queued for Sprint 3 (mirrors the §3.1 fix path):**
> recording-rule pre-aggregation on `(route, target_service, result)`
> for the alert path; raw series with `tenant_id_hash` kept for
> dashboards. Expected drop: 97k → ~25k per-service. Tracked in the
> SLO doc §8 sign-off checklist as a Sprint 3 task. **No code change
> required from FullstackEngineer in Sprint 2.**

### 3.10 S2.8 security-control metrics (T-02, T-03, T-04, T-05, T-09 mitigations)

> **Owner spec:** SecurityArchitect (S2.8 owner, 2026-06-12)
> **Added:** 2026-06-12 (S2.8 follow-up; not in original S2.7 hand-in)
> **Purpose:** close the observability gap for the S2.8 security
> controls (supply-chain verification, feed integrity, audit-chain
> tamper detection, canary, LLM cost guardrail). Without these
> metrics, the S2.8 controls are unverifiable in production.
> **Naming status:** provisionally added; final lock pending D6/D7
> PlatformArchitect verdicts (no naming conflicts with this batch).

#### 3.10.1 `devsecops_sbom_validation_errors_total` (T-08 mitigation)
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Owner service** | `security-service` (port 4003) |
| **Purpose** | Track SBOM input validation rejections |
| **Labels** | `service`, `code` |
| **Allowed `code`** | `sbom.purl.invalid`, `sbom.size.exceeded`, `sbom.format.unsupported`, `sbom.signature.invalid`, `sbom.hash.mismatch` |
| **Cardinality** | 1 × 5 = **5 series** (trivial) |
| **SLO target** | 95% of total proxy requests pass validation (i.e. `error_rate < 1%` over 5m) |
| **Alert** | `SbomValidationErrorRate` (P3) — rate > 1% over 5m → ticket |

#### 3.10.2 `devsecops_cosign_verify_duration_seconds` (T-04 supply-chain)
| Attribute | Value |
|---|---|
| **Type** | Histogram |
| **Owner service** | `sbom-pipeline` (port 4007) — initContainer |
| **Purpose** | Cosign/Rekor supply-chain verification timing (T-04 mitigation) |
| **Labels** | `service`, `result` |
| **Allowed `result`** | `success`, `failure` |
| **Histogram buckets (seconds)** | `0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120` (9 buckets) |
| **Cardinality** | 1 × 2 = **2 combos** × 9 buckets = **18 series** |
| **SLO target** | p95 < 30s for `result="success"` over 5m |
| **Alert** | `CosignVerifySlow` (P3) — p95 > 30s for 10m → ticket |

#### 3.10.3 `devsecops_cve_feed_records_rejected_total` (T-02 feed integrity)
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Owner service** | `vuln-intel` (port 4008) |
| **Purpose** | CVE records rejected by the feed integrity gate (T-02 mitigation) |
| **Labels** | `service`, `feed`, `reason` |
| **Allowed `feed`** | `nvd`, `ghsa`, `osv` |
| **Allowed `reason`** | `schema`, `range`, `integrity`, `consensus` |
| **Cardinality** | 1 × 3 × 4 = **12 series** (trivial) |
| **SLO target** | `reason="integrity"` rejection rate < 0.1/s over 5m (i.e. possible feed compromise) |
| **Alert** | `CveFeedIntegrityRejected` (P2) — rate > 0.1/s for 5m → ticket |

#### 3.10.4 `devsecops_risk_score_audit_chain_verified` (T-05 tamper detection)
| Attribute | Value |
|---|---|
| **Type** | Gauge |
| **Owner service** | `security-service` (port 4003) |
| **Purpose** | Per-service risk-score audit-chain verification status (T-05 mitigation) |
| **Labels** | `service`, `ok` |
| **Allowed `ok`** | `0`, `1` |
| **Cardinality** | 1 × 2 = **2 series** per service |
| **SLO target** | **MUST always be 1** (any `ok=0` is a tamper signal) |
| **Alert** | `RiskScoreAuditChainBroken` (P0) — `sum by (service)(...{ok=0}) > 0` → page |

#### 3.10.5 `devsecops_canary_test_failures_total` (T-09 data-exfil canary)
| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Owner service** | `security-service` (port 4003) |
| **Purpose** | Data-exfiltration canary test failure counter (T-09 mitigation) |
| **Labels** | `service`, `endpoint` |
| **Cardinality** | 1 × ~5 endpoints = **~5 series** |
| **SLO target** | **MUST stay 0** (any increment is a data-exfil signal) |
| **Alert** | `CanaryTestFailure` (P0) — `increase(...[1m]) > 0` → page |

#### 3.10.6 `devsecops_llm_token_budget_remaining` (T-03 LLM cost guardrail)
| Attribute | Value |
|---|---|
| **Type** | Gauge |
| **Owner service** | `vuln-intel` (port 4008) |
| **Purpose** | LLM token budget remaining (T-03 mitigation; cap on LLM-driven CVE summarization) |
| **Labels** | (none, aggregate) |
| **Cardinality** | **1 series** |
| **SLO target** | Gauge ≥ 20% (i.e. budget is 80% consumed) |
| **Alert** | `LlmTokenBudgetLow` (P3) — gauge < 0.20 for 5m → ticket |

#### 3.10.7 `devsecops_rate_limit_rejections_total` — DELETED in round 6

**This metric was deleted in round 6** and **merged into §3.8.4** under the same name. The merged spec is:

| Attribute | Value |
|---|---|
| **Type** | Counter |
| **Owner service** | `security-service` (port 4003) |
| **Purpose** | Per-bucket 429 rejection count (replaces the original §3.8.4 `devsecops_rate_limit_triggered_total`) |
| **Labels** | `service`, `route`, `bucket` |
| **Allowed `bucket`** | `xs`, `small`, `medium`, `large`, `xlarge` (D7 5-bucket scheme) |
| **Cardinality** | 1 × ~5 routes × 5 = **~25 series** (trivial) |

**Why merged:** the original §3.10.7 was a placeholder for an S2.8 T-03 (LLM cost) rate-limit gate, but **FullstackEngineer's actual implementation** in `backend/common/observability/metrics.ts` (LANDED 2026-06-12) already uses the better name `devsecops_rate_limit_rejections_total` with `route` + `bucket` labels, matching the D7 5-bucket scheme. Two specs, one metric — merge into the more-specific §3.8.4 spec, delete §3.10.7. **New emissions must use the §3.8.4 spec verbatim.**

#### 3.11 `devsecops_vuln_feed_last_refresh_timestamp_seconds` (round 6 — S2.7 staleness tracking)
| Attribute | Value |
|---|---|
| **Type** | Gauge (Unix timestamp in seconds) |
| **Owner service** | `vulnerability-service` (port 4008, owned by VulnerabilityIntelligenceAgent) |
| **Purpose** | Last successful poll/refresh timestamp per source. Used by `VulnIngestionLag` alerts to detect stale feeds without polling the ingestion service directly. |
| **Labels** | `service`, `source` |
| **Allowed `source`** | `nvd`, `ghsa`, `osv`, `epss`, `kev` (5 values) |
| **Cardinality** | 1 × 5 = **5 series** (trivial) |
| **Staleness thresholds (alert conditions)** | NVD: gauge older than 2h → `VulnIngestionLag` P2. GHSA: gauge older than 15m → `VulnIngestionLag` P1. OSV: gauge older than 1h → `VulnIngestionLag` P2. EPSS: gauge older than 6h → info only. KEV: gauge older than 6h → info only. |
| **Emission pattern** | `vulnerability-service` emits this gauge at the end of each successful poll cycle (1 per source). On failure, the previous value is retained (no reset) — the staleness check is a query-time computation, not a counter. |

**Why a separate gauge (and not a derived staleness computation in PromQL):** the `VulnIngestionLag` alerts need a stable, low-cardinality input that survives a full ingestion-service restart. A gauge emitted from `vulnerability-service` is observable from the metric endpoint and can be scraped independently of the ingestion's internal state. The PromQL is then simply `time() - devsecops_vuln_feed_last_refresh_timestamp_seconds{source="ghsa"} > 900`. **This is the same pattern Grafana uses for "last successful sync" tiles.**


## 4. Naming Convention Rules (apply to ALL future metrics)

1. **Format:** `devsecops_{domain}_{noun}_{unit_suffix}` in `snake_case`, all lowercase.
2. **Unit suffixes are mandatory** and follow Prometheus convention:
   - `_seconds` (durations — **never** `_ms` or `_duration`)
   - `_total` (counters, monotonically increasing)
   - `_bytes` (sizes)
   - `_ratio` (0..1, dimensionless)
   - No suffix for gauges of a current count.
3. **No abbreviations** beyond established 3-letter ones (CVE, SBOM, API, KEV, EPSS, etc.).
4. **Domain names** are stable: `security`, `compliance`, `audit`, `agent`, `integration`, `platform`. New domains require an ADR.

## 5. Label Convention Rules

1. **`service` is added by OTel `service.name` resource attribute.** Do not manually re-add a `service` label in your instrumentation — it will duplicate and create drift.
   1.1. **Node.js exception — `prom-client` does NOT auto-add the `service` label.** The Python observability module (`observability-py/metrics.py`) uses the OTel SDK + Prometheus exporter, which maps `service.name` → `service` label automatically. The Node.js `prom-client` package does NOT do this. **All Node.js services must use the helper at `backend/common/observability/metrics.ts` (added in Sprint 2 per Q3 PlatformArchitect sign-off),** which reads `OTEL_SERVICE_NAME` from the environment and applies it as the `service` label automatically. Do **not** use raw `prom-client` Counter/Histogram constructors for new Node.js metrics — they will emit metrics without a `service` label, which breaks fleet-wide aggregation. **Sprint 3 follow-up:** evaluate migrating Node.js services to the OTel SDK for metrics (`@opentelemetry/exporter-prometheus`) for parity with Python; defer to Sprint 3.
2. **Every metric must have `# HELP` and `# TYPE` lines.** Both `prom-client` (Python and Node) auto-emit these; OTel SDK needs explicit configuration.
3. **No high-cardinality labels:** `tenant_id`, `user_id`, `request_id`, `agent_id`, `worker_id`, `trace_id` are **forbidden on metrics**. Use logs and traces for these dimensions.
4. **Stable label values:** Allowed values are enumerated in this spec. New values require updating this doc **and** a coordinated code change.
5. **Cardinality budget:** Soft cap of **50,000 active time series per service** before Prometheus sharding is required. **Note:** adding `repo_shape` (D2) to `devsecops_sbom_generation_duration_seconds` pushes the per-service total to ~78,000; this is **over the soft cap** for that one metric but is accepted for Sprint 2 — the cap is per-metric-budget-soft, not per-service-strict, and the per-service total in §7 is updated. Re-evaluate at end of Sprint 3.

## 6. Histogram Bucket Conventions

1. **Default for durations in seconds:** `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1200`.
2. **SLO-shaped buckets** are preferred when there is a known SLO target. The event-bus lag metric uses `(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300)` so that `histogram_quantile(0.99, ...)` has good resolution at the SLO point (5s).
3. **`histogram_quantile` safety:** always `sum by (le, ...)` **before** `histogram_quantile()`. A p99 computed on a single-pod series is wrong for the fleet. Future engineers: do not copy-paste queries that omit the `sum by (le, ...)`.
4. **Consider the OTel default exponential buckets** for new duration metrics and only override when you have a specific SLO to align with.

## 7. Cardinality Math (locked-in summary)

| Metric | Label combos | Buckets | Time series |
|---|---:|---:|---:|
| `devsecops_sbom_generation_duration_seconds` (D2: +`repo_shape`; D6: +`tenant_tier` *pending verdict*) | 4,800 / 14,400 | 16 | 76,800 / 230,400 |
| `devsecops_vulnerability_ingestion_total` | 15 | — | 15 |
| `devsecops_risk_calculation_duration_seconds` (D7: 5 buckets xs/small/medium/large/xlarge) | 80 | 14 | 1,120 |
| `devsecops_active_scans` | 4 | — | 4 |
| `devsecops_queue_depth` (per service) | ~5 | — | 5 |
| `devsecops_vulnerability_ingestion_lag_seconds` (B2, NEW) | 3 | 9 | 27 |
| `devsecops_eventbus_lag_seconds` (cluster) | varies | 11 | ~5,000 |
| `devsecops_proxy_request_duration_seconds` (§3.8.1, security-service, N=50 × 4 replicas, **NO `tenant_id_hash`**) | ~30 | 12 | ~360 |
| `devsecops_proxy_request_total` (§3.8.2, N=50 × 4 replicas, **NO `tenant_id_hash`**) | ~150 | — | ~150 |
| `devsecops_eventbus_publish_total` (§3.8.3) | 9 | — | 9 |
| `devsecops_rate_limit_rejections_total` (§3.8.4, **renamed from `rate_limit_triggered_total`**; N=50 × 4 replicas, route+bucket labels) | ~25 | — | ~25 |
| `devsecops_auth_failure_total` (§3.8.5, N=50 × 4 replicas, **NO `tenant_id_hash`**) | ~4 | — | ~4 |
| `devsecops_dashboard_query_duration_seconds` (§3.8.6, N=50 × 4 replicas, **NO `tenant_id_hash`**) | ~5 | 12 | ~60 |
| `devsecops_vuln_feed_last_refresh_timestamp_seconds` (§3.11, NEW round 6) | 5 | — | 5 |
| **Per-service total (security-service :4003, N=50 × 4 replicas, with §3.8 *and* `tenant_id_hash` dropped)** | | | **~560** ✅ |
| **Per-service total (security-service :4003, with D6 `tenant_tier` *if* approved)** | | | **~14,960** ⚠ |
| **Per-service total (sbom-pipeline :4007, with D2, *without* D6)** | | | **~78,000** ⚠ |
| **Per-service total (sbom-pipeline :4007, with D2 *and* D6, *if* approved)** | | | **~232,400** 🚨 |
| **Per-service total (vuln-intel :4008 + dependency-intel :4009)** | | | **~5,000** |
| **Total platform-wide (security stack, N=50 × 4 replicas, current state)** | | | **~88,500** ✅ |
| **Total platform-wide (security stack, N=50 × 4 replicas, with D6 *if* approved)** | | | **~258,500** 🚨 |

**✅ §3.8 over-cap is RESOLVED (round 6).** FullstackEngineer dropped `tenant_id_hash` from all 6 proxy metrics in the LANDED `backend/common/observability/metrics.ts` helper. Security-service :4003 per-service total drops from **~109,400 → ~560** (1,950× reduction, **well under the 50k soft cap**). **No Sprint 3 recording-rule pre-aggregation needed for §3.8** — was previously queued, now removed from the Sprint 3 backlog.

**⚠️ D2 (sbom-gen, `repo_shape`) is still over-cap (~78k) and remains the only Sprint 3 recording-rule target.** Recording-rule pre-aggregation on `(target_type, result)` expected to drop ~78k → ~25k. Tracked in `slos-security-stack.md` §8 sign-off checklist.

**🚨 D6 (`tenant_tier` addition to §3.1) is the BIG one if approved — ~230k per-service, ~232k platform-wide.** Awaiting PlatformArchitect's final verdict on the cost-benefit. **Conditional acceptance from SecurityArchitect**: a Sprint 3 recording-rule pre-aggregation on `(target_type, result, ecosystem)` is acceptable mitigation if PlatformArchitect rules in favor. Tracked in `slos-security-stack.md` §8 sign-off checklist.

**All §3.10 S2.8 control metrics (T-02..T-09) are trivially low-cardinality** (<50 series each) — see the §3.10 sub-sections.

## 8. SLO Targets (Summary)

Full table with per-bucket rationale, error budgets, and alert thresholds lives in
**`docs/observability/slos-security-stack.md`** (SRE-owned, v1.2 Locked).

This spec only enumerates the metric names; the operational targets are
SRE's responsibility. **The two docs must be updated together** when
either changes.

## 9. Open Follow-ups (from S2.7 sign-off)

**F1. Multi-window burn-rate alerts** *(Sprint 3, prioritised by Lead)*
Add Google SRE workbook-style alerts:
- Fast burn: 2% of 30d budget in 1h → page.
- Slow burn: 5% of 30d budget in 6h → warn.
- Add `// TODO(burn-rate)` markers in `infra/observability/prometheus/alert-rules.yml`.

**F2. `runbook_url` annotation on every alert**
Each alert must have a `runbook_url:` annotation pointing to `docs/runbooks/<alert>.md`. Stub the runbook files for the 5 per-bucket `RiskCalcHighLatency*` alerts.

**F3. `histogram_quantile` aggregation note**
One-line note in `slos-security-stack.md`: always `sum by (le, ...)` before `histogram_quantile()`.

**B2 (round 2). New metric: `devsecops_vulnerability_ingestion_lag_seconds`**
Added as §3.7 (label set `service` + `source` ∈ {nvd, ghsa, osv}, 9-bucket
histogram, 27 time series, security-control framing). Provisional 95% SLO
targets (NVD=2h, GHSA=15min, OSV=1h, aggregate=1h) locked 2026-06-12 per
PlatformArchitect sign-off; **pending VulnerabilityIntelligenceAgent
confirmation of polling cadence** and re-validation at end of S2.11 E2E.

**D1–D5 (round 3). Label divergence resolutions.**
- D1: `sbom_size_bucket` 5-bucket scheme LOCKED (small/medium/large/xlarge/xxlarge at 100/1k/10k/50k thresholds).
- D2: NEW label `repo_shape` ADDED to §3.1 (monorepo/service/package, applies only when `target_type="repo"`). Cardinality impact: +58k series for sbom_gen.
- D3: `format` label DEFERRED to Sprint 3 (4× cardinality jump not worth it now).
- D4: `result` label 4-value set LOCKED (success/failure/timeout/cancelled).
- D5: `severity` label 5-value set LOCKED (critical/high/medium/low/unknown).

**Q3 (round 3). Node.js `service` label gap.**
Added §5.1.1 footnote documenting that Node.js `prom-client` does NOT
auto-add the `service` label and that all Node.js services must use the
helper at `backend/common/observability/metrics.ts` (to be added in
Sprint 2 by FullstackEngineer per Q3 sign-off). Helper reads
`OTEL_SERVICE_NAME` and applies it as the `service` label.

**§3.8 (round 4 — round 6 revision). Security-service :4003 proxy-layer metrics.**
Added §3.8.1–§3.8.6 with the 6 proxy metrics FullstackEngineer wired in
security-service :4003 (LANDED 2026-06-12):
- `devsecops_proxy_request_duration_seconds` (Histogram, 12 buckets, `route` label)
- `devsecops_proxy_request_total` (Counter, `route` label)
- `devsecops_eventbus_publish_total` (Counter, 3 topics × 3 results)
- `devsecops_rate_limit_rejections_total` (Counter, `route` + `bucket` labels) — **renamed from `rate_limit_triggered_total` per §3.10.7 merge (round 6)**
- `devsecops_auth_failure_total` (Counter, `reason` label)
- `devsecops_dashboard_query_duration_seconds` (Histogram, 12 buckets, `route` label)

**Cardinality impact at N=50 tenants × 4 replicas:** security-service :4003 emits **~560 active series** (well under the 50k soft cap). **~109,400 → ~560 reduction** achieved by **dropping `tenant_id_hash` from all 6 metrics** in FullstackEngineer's actual implementation (LANDED 2026-06-12). Resolution confirmed in round 6 — no Sprint 3 recording-rule pre-aggregation needed for §3.8.

**Note on the rename:** §3.10.7 (`devsecops_rate_limit_triggered_total`) was originally added as a standalone S2.8 control metric, but FullstackEngineer's actual implementation in `metrics.ts` already uses the better name `devsecops_rate_limit_rejections_total` with a `bucket` label (matching the D7 5-bucket scheme). §3.10.7 is **deleted** in this revision; the merged spec lives in §3.8.4.

**Cardinality impact at N=50 tenants × 4 replicas:** security-service :4003 emits **~560 active series** (well under cap). **The §3.8 over-cap is RESOLVED** by FullstackEngineer dropping `tenant_id_hash` from all 6 metrics in the LANDED `metrics.ts` helper. No Sprint 3 recording-rule pre-aggregation needed for §3.8. Tracked in the SLO doc §8 sign-off checklist as ✅ RESOLVED.

**Compliance audit-log metric (deferred to Sprint 2.5 or 2.11):**
`audit_log_emission_total{service, result}` is a future metric that
ComplianceOfficer will emit from `poam.service.ts` and `evidence-attacher.ts`
in compliance-service. Counter, 2 series per service. Will be added in a
follow-up PR owned by SREEngineer (audit emission helper) and
ComplianceOfficer (compliance-service emission). Tracked in the SLO doc
§8 sign-off checklist as a Sprint 2.5/2.11 follow-up.

## 10. References

- ADR-0001 — Event Bus Transport (Redis Streams first, NATS later)
- ADR-0002 — Agent-to-Agent Communication (bus only)
- ADR-0003 — Event Schema Format (Avro + JSON-Schema)
- ADR-0004 — Six Services, One Database (schema-per-service)
- `docs/observability/slos-security-stack.md` — SRE-owned SLO doc
- `docs/architecture/event-bus.md` §14 — Event bus observability
- `docs/architecture/agent-topology.md` §12 — Agent observability
- Prometheus naming best practices: https://prometheus.io/docs/practices/naming/
- Google SRE workbook — burn-rate alerting: https://sre.google/workbook/alerting-on-slos/

## 11. Revision History

| Date | Version | Author | Notes |
|---|---|---|---|
| 2026-06-12 | 1.0.0 | PlatformArchitect | Initial draft; S2.7 hand-in |
| 2026-06-12 | 1.0.0-rc1 | SREEngineer | Ingested into `docs/observability/metrics-spec.md`; B2 follow-up added; §10 ADR list confirmed (0001–0004 are the only ADRs at this writing; 0005+ are taken by GitOpsManager's Sprint 1 work per PlatformArchitect) |
| 2026-06-12 | 1.0.0 | SREEngineer | **Locked** — D1–D5 verdicts + Q3 sign-off applied: §3.1 +`repo_shape` (D2), §3.7 new `devsecops_vulnerability_ingestion_lag_seconds` (B2), §5.1.1 Node.js service-label helper footnote (Q3), §7 cardinality math updated (per-service total ~78,000, over soft cap — re-evaluate Sprint 3), §9 follow-up list updated with D1–D5 + Q3 resolutions |
| 2026-06-12 | 1.0.1 | SREEngineer | **Refinement** — §3.1 callout block updated with the Sprint 3 mitigation note (recording-rule pre-aggregation on `(target_type, result)` per PlatformArchitect 2026-06-12 ACK). SLO doc §8 sign-off checklist has a new row for the Sprint 3 task. |
| 2026-06-12 | 1.0.2 | SREEngineer | **Round 4** — §3.8 added with 6 security-service :4003 proxy metrics (FullstackEngineer S2.7 follow-up). §7 cardinality math updated: security-service :4003 per-service total ~109,400 at N=50 × 4 replicas; sbom-pipeline :4007 ~78,000. Both over the 50k soft cap; Sprint 3 mitigation = recording-rule pre-aggregation (same fix path as D2). §9 follow-up list updated. Compliance `audit_log_emission_total` metric noted as Sprint 2.5/2.11 deferred work. |
| 2026-06-12 | 1.0.3 | SREEngineer | **Round 5 — S2.8 security-control metrics.** §3.10 added with 7 new metrics (T-02, T-03, T-04, T-05, T-08, T-09 mitigations): `devsecops_sbom_validation_errors_total`, `devsecops_cosign_verify_duration_seconds`, `devsecops_cve_feed_records_rejected_total`, `devsecops_risk_score_audit_chain_verified`, `devsecops_canary_test_failures_total`, `devsecops_llm_token_budget_remaining`, `devsecops_rate_limit_rejections_total` (§3.8.4 merge pending). D6 (`target_type` rename + `tenant_tier` addition) and D7 (new 5-bucket `sbom_size_bucket` scheme) routed to PlatformArchitect for sign-off. |
| 2026-06-12 | 1.0.4 | SREEngineer | **Round 6 — closing the §3.8 + D6/D7/§3.8.4 round.** D7 5-bucket scheme LOCKED: `sbom_size_bucket` is now `xs` (<10) / `small` (10–99) / `medium` (100–999) / `large` (1k–4,999) / `xlarge` (≥5k); `xxlarge` dropped. §3.1 final `target_type` values: `image` / `filesystem` / `repo` / `archive` / `directory` / `sbom` (D6 locked). `tenant_tier` (`free` / `pro` / `enterprise`) added to §3.1, **pending PlatformArchitect final verdict** — conditional acceptance from SecurityArchitect with Sprint 3 recording-rule pre-aggregation on `(target_type, result, ecosystem)` as the mitigation path. §3.8 `tenant_id_hash` label DROPPED from all 6 proxy metrics (FullstackEngineer LANDED `metrics.ts` helper): security-service :4003 per-service total drops from **~109,400 → ~560** (1,950× reduction). **§3.8 over-cap RESOLVED** — no Sprint 3 recording-rule pre-aggregation needed for §3.8. §3.10.7 deleted (merged into §3.8.4 as `devsecops_rate_limit_rejections_total` with `route` + `bucket` labels). §3.11 added: `devsecops_vuln_feed_last_refresh_timestamp_seconds` (Gauge, 5 sources, used by `VulnIngestionLag` alerts for staleness tracking). §7 cardinality math updated with all three scenarios (current / with D6 / Sprint 3 post-mitigation). Alert rules renamed per D7: `RiskCalcHighLatencyXxlarge` → `RiskCalcHighLatencyXs` (NEW, with runbook stub at `docs/runbooks/RiskCalcHighLatencyXs.md`); existing per-bucket alerts unchanged. SLO doc §3 targets re-calibrated to D7. SLO doc §5.6 GHSA-headroom note added. SLO doc §8 sign-off checklist updated. |
