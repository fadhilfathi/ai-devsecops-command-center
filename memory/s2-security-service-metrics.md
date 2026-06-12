---
name: S2.7 Security-Stack Metric Naming (security-service :4003 proxy layer)
description: Proposed 6 new Prometheus metrics for the security-service :4003 proxy layer, naming convention alignment with SREEngineer, ownership map across the 4 security services, and answers to the two label-set questions.
type: project
---

# S2.7 — Security-Stack Metric Naming (security-service :4003 scope)

## Context
- SREEngineer started S2.7 (Runtime Observability for Security Stack).
- Already delivered: `backend/common/observability-py/` toolkit, per-service observability hooks, 4 alert rules, Grafana dashboard, runbook v1.1, docker-compose 3 Python services.
- Memory: `memory/s2-runtime-observability.md` (canonical S2.7 deliverable; my S2.7 memory is supplementary, covering only security-service :4003 proxy layer).

## Proposed metrics for security-service :4003 (my scope)
| Metric | Type | Labels | Cardinality |
|---|---|---|---|
| `devsecops_proxy_request_duration_seconds` | Histogram | `{route, target_service, result}` | 5 routes × 3 targets × 2 results = 30 series × ~8 buckets = 240 |
| `devsecops_proxy_request_total` | Counter | `{route, target_service, status_code}` | 5 × 3 × ~6 = 90 |
| `devsecops_eventbus_publish_total` | Counter | `{topic, result}` | 3 topics × 3 results = 9 |
| `devsecops_rate_limit_triggered_total` | Counter | `{route}` | 5 |
| `devsecops_auth_failure_total` | Counter | `{route, reason}` | 5 × 4 reasons = 20 |
| `devsecops_dashboard_query_duration_seconds` | Histogram | `{endpoint}` | 1 × ~8 buckets = 8 |

All follow `devsecops_{domain}_{noun}_{unit_suffix}` per PlatformArchitect Decision #11.

## Answers to SREEngineer's two questions
1. **`devsecops_sbom_generation_duration_seconds` labels** — security-service :4003 does NOT emit this (sbom-pipeline :4007 is primary owner). I emit `devsecops_proxy_request_duration_seconds` instead. No additional labels from my side for the Python metric.
2. **`sbom_size_bucket` thresholds** — confirmed small=<100, medium=100-1k, large=1k-10k, xlarge=>=10k; recommended extending to 5 buckets (add xxlarge=>=50k) to match PlatformArchitect's locked scheme. Non-breaking.

## Ownership map (locked by me 2026-06-12)
- **security-service :4003 (FullstackEngineer):** owns the 6 proxy-layer metrics above
- **sbom-pipeline :4007 (SBOMPipelineAgent):** owns `devsecops_sbom_generation_duration_seconds`, `devsecops_active_scans{scanner_type="syft"}`, `devsecops_queue_depth{queue_name="sbom_jobs"}`
- **vuln-intel :4008 (VulnerabilityIntelligenceAgent):** owns `devsecops_vulnerability_ingestion_total`, `devsecops_queue_depth{queue_name="cve_processing"}`, `devsecops_vuln_feed_last_refresh_timestamp_seconds`
- **dependency-intel :4009 (VulnerabilityIntelligenceAgent):** owns `devsecops_risk_calculation_duration_seconds`
- **All 3 Python services:** emit `devsecops_eventbus_lag_seconds` (platform SLI, PlatformArchitect)

## Open question for SRE
- Final approval on the 6 metric names + labels
- Pointer to `@aicc/metrics` package OR guidance on whether to use in-process `prom-client` default registry
- Will not start implementation until both are confirmed
