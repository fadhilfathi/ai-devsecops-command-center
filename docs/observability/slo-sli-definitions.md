# SLO & SLI Definitions — Service Catalog

> **Sprint:** 1 — Foundations
> **Owner:** SREEngineer
> **Status:** Draft v1.0
> **Last Updated:** 2026-06-12
> **Companion doc:** [`monitoring-architecture.md`](./monitoring-architecture.md)

This catalog defines the **Service Level Indicators (SLIs)**, **Service Level Objectives (SLOs)**, and **error budget policies** for every backend service in the AI-DevSecOps Command Center. Every service must be in this catalog before it can be promoted to production.

---

## 1. SLO Authoring Conventions

- **Window:** all SLOs use a rolling **30-day** window.
- **Targets:** expressed as a ratio in `[0, 1]`. `0.999` = 99.9%.
- **Budget:** `1 - target` over the window, expressed in minutes.
- **Burn-rate alerts:** see [`alerting-runbooks.md`](./alerting-runbooks.md) §3 for the multi-window rules.
- **Review cadence:** quarterly. A change to an SLO is a breaking change for downstream consumers and requires sign-off from Product, Security, and SRE.

---

## 2. Auth Service (`auth`)

**Purpose:** Issue and validate JWTs, manage sessions, expose OIDC discovery.

### SLIs

| Name              | Type        | Query                                                                                                  |
|-------------------|-------------|--------------------------------------------------------------------------------------------------------|
| `availability`    | throughput  | `sum(rate(http_requests_total{service="auth",status!~"5.."}[5m])) / sum(rate(http_requests_total{service="auth"}[5m]))` |
| `login_latency`   | latency     | `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{service="auth",route="/login"}[5m])))` |
| `token_latency`   | latency     | `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{service="auth",route="/token"}[5m])))` |
| `token_correctness` | correctness | `sum(rate(jwt_validation_total{result="valid"}[5m])) / sum(rate(jwt_validation_total[5m]))`            |

### SLOs

| SLI                  | Target  | Window | Budget / 30d | Notes                                              |
|----------------------|---------|--------|--------------|----------------------------------------------------|
| `availability`       | 0.999   | 30d    | 43.2 min     | Excludes `/healthz` probes.                        |
| `login_latency` < 500ms | 0.95 | 30d    | 36 h         | p99 < 500 ms.                                      |
| `token_latency` < 250ms | 0.95 | 30d    | 36 h         | p99 < 250 ms.                                      |
| `token_correctness`  | 0.99999 | 30d    | 0.43 min     | Valid tokens must validate. Hard cap.              |

### Error Budget Policy

- **Budget exhaustion → deploy freeze** for the `auth` service until the rolling window recovers.
- **Token correctness SLO breach** triggers a P0 incident and immediate SecurityArchitect notification.

---

## 3. Agent Service (`agent`)

**Purpose:** Orchestrate AI agents (scanner, analyst, remediator, etc.) and broker their work via the event bus.

### SLIs

| Name                   | Type        | Query                                                                                              |
|------------------------|-------------|----------------------------------------------------------------------------------------------------|
| `availability`         | throughput  | `sum(rate(http_requests_total{service="agent",status!~"5.."}[5m])) / sum(rate(http_requests_total{service="agent"}[5m]))` |
| `task_duration`        | latency     | `histogram_quantile(0.99, sum by (le) (rate(agent_task_duration_seconds_bucket{service="agent"}[5m]))` )` |
| `task_success_rate`    | correctness | `sum(rate(agent_tasks_total{outcome="success"}[5m])) / sum(rate(agent_tasks_total[5m]))`           |
| `queue_depth_ok`       | saturation  | `agent_tasks_in_flight{service="agent"} < 1000`                                                   |

### SLOs

| SLI                  | Target  | Window | Budget / 30d | Notes                                                  |
|----------------------|---------|--------|--------------|--------------------------------------------------------|
| `availability`       | 0.995   | 30d    | 3.6 h        | Some agent failures are recoverable.                   |
| `task_duration` p99 < 60s | 0.90 | 30d    | 72 h         | End-to-end agent task; excludes LLM provider time.     |
| `task_success_rate`  | 0.95    | 30d    | 36 h         | Successful completion / total tasks.                   |
| `queue_depth_ok`     | 0.99    | 30d    | 7.2 h        | Queue depth below soft cap.                            |

### Notes

- LLM-provider latency is **excluded** from `task_duration` because it is outside our control; we measure a separate `llm_latency` SLI internally.
- Agent SLOs are intentionally looser than the Auth service because they involve stochastic model output.

---

## 4. Security Service (`security`)

**Purpose:** Run vulnerability scans, manage CVE feeds, produce SBOMs.

### SLIs

| Name                   | Type        | Query                                                                                              |
|------------------------|-------------|----------------------------------------------------------------------------------------------------|
| `availability`         | throughput  | `sum(rate(http_requests_total{service="security",status!~"5.."}[5m])) / sum(rate(http_requests_total{service="security"}[5m]))` |
| `scan_completion_rate` | correctness | `sum(rate(scans_completed_total[5m])) / sum(rate(scans_started_total[5m]))`                        |
| `scan_freshness`       | freshness   | `time() - max(security_last_scan_timestamp_seconds)`                                              |
| `sbom_generation_rate` | throughput  | `sum(rate(sbom_artifacts_generated_total[5m]))`                                                   |

### SLOs

| SLI                   | Target  | Window | Budget / 30d | Notes                                                   |
|-----------------------|---------|--------|--------------|---------------------------------------------------------|
| `availability`        | 0.99    | 30d    | 7.2 h        |                                                         |
| `scan_completion_rate`| 0.98    | 30d    | 14.4 h       | Canceled or errored scans count as failures.            |
| `scan_freshness` < 24h | 0.95   | 30d    | 36 h         | 95% of assets scanned in the last 24h.                  |
| `sbom_generation_rate`| 0.95    | 30d    | 36 h         | Of started SBOM jobs, 95% produce an artifact.          |

---

## 5. Incident Service (`incident`)

**Purpose:** Detect, group, deduplicate, and route security/operational incidents.

### SLIs

| Name                | Type        | Query                                                                                              |
|---------------------|-------------|----------------------------------------------------------------------------------------------------|
| `availability`      | throughput  | `sum(rate(http_requests_total{service="incident",status!~"5.."}[5m])) / sum(rate(http_requests_total{service="incident"}[5m]))` |
| `mttd`              | latency     | `histogram_quantile(0.5, sum by (le) (rate(incident_time_to_detect_seconds_bucket[5m])))`         |
| `mttr_p1`           | latency     | `histogram_quantile(0.5, sum by (le) (rate(incident_time_to_resolve_seconds_bucket{severity="P1"}[5m])))` |
| `notification_delivery` | correctness | `sum(rate(notifications_sent_total{outcome="delivered"}[5m])) / sum(rate(notifications_sent_total[5m]))` |

### SLOs

| SLI                     | Target  | Window | Budget / 30d | Notes                                          |
|-------------------------|---------|--------|--------------|------------------------------------------------|
| `availability`          | 0.999   | 30d    | 43.2 min     |                                                |
| `mttd` < 5 min (P1)     | 0.90    | 30d    | 72 h         | Median time-to-detect under 5 min for P1.      |
| `mttr_p1` < 60 min      | 0.80    | 30d    | 144 h        | Median time-to-resolve under 60 min for P1.    |
| `notification_delivery` | 0.999   | 30d    | 43.2 min     | Delivered / total notifications sent.          |

---

## 6. Compliance Service (`compliance`)

**Purpose:** Evaluate CIS/NIST controls, collect evidence, produce posture reports.

### SLIs

| Name                | Type        | Query                                                                                              |
|---------------------|-------------|----------------------------------------------------------------------------------------------------|
| `availability`      | throughput  | `sum(rate(http_requests_total{service="compliance",status!~"5.."}[5m])) / sum(rate(http_requests_total{service="compliance"}[5m]))` |
| `control_eval_rate` | correctness | `sum(rate(compliance_evaluations_total{outcome="pass"}[5m])) / sum(rate(compliance_evaluations_total[5m]))` |
| `evidence_freshness`| freshness   | `time() - max(compliance_evidence_last_collected_seconds)`                                         |

### SLOs

| SLI                     | Target  | Window | Budget / 30d | Notes                                                |
|-------------------------|---------|--------|--------------|------------------------------------------------------|
| `availability`          | 0.999   | 30d    | 43.2 min     |                                                      |
| `control_eval_rate`     | 0.98    | 30d    | 14.4 h       | Evaluations returning "pass" / total.                |
| `evidence_freshness` < 24h | 0.99 | 30d    | 7.2 h        | 99% of frameworks' evidence < 24h old.               |

---

## 7. Integration Service (`integration`)

**Purpose:** Bridge external systems (GitHub, Jira, Slack, SIEM, etc.).

### SLIs

| Name                  | Type        | Query                                                                                              |
|-----------------------|-------------|----------------------------------------------------------------------------------------------------|
| `availability`        | throughput  | `sum(rate(http_requests_total{service="integration",status!~"5.."}[5m])) / sum(rate(http_requests_total{service="integration"}[5m]))` |
| `webhook_delivery`    | correctness | `sum(rate(webhook_deliveries_total{outcome="success"}[5m])) / sum(rate(webhook_deliveries_total[5m]))` |
| `api_call_latency`    | latency     | `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket{service="integration"}[5m]))` )` |
| `github_rate_limit`   | saturation  | `github_rate_limit_remaining / github_rate_limit_max > 0.1`                                        |

### SLOs

| SLI                  | Target  | Window | Budget / 30d | Notes                                                |
|----------------------|---------|--------|--------------|------------------------------------------------------|
| `availability`       | 0.995   | 30d    | 3.6 h        |                                                      |
| `webhook_delivery`   | 0.99    | 30d    | 7.2 h        | Successful delivery / total deliveries.              |
| `api_call_latency` < 1s p99 | 0.95 | 30d | 36 h     | For inbound API calls to this service.               |
| `github_rate_limit`  | 0.999   | 30d    | 43.2 min     | Staying above 10% of the GitHub rate-limit budget.   |

---

## 8. Platform SLIs (cross-cutting)

These SLIs are not owned by a single service but measured across the platform.

| SLI                    | Query                                                                                              | Target  | Notes                                       |
|------------------------|----------------------------------------------------------------------------------------------------|---------|---------------------------------------------|
| `api_availability`     | `sum(rate(http_requests_total{status!~"5.."}[5m])) / sum(rate(http_requests_total[5m]))`            | 0.999   | All user-facing endpoints.                  |
| `api_p99_latency`      | `histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))`            | < 1 s   | Tail latency for the slowest user route.    |
| `event_bus_lag`        | `histogram_quantile(0.99, sum by (le) (rate(event_bus_lag_seconds_bucket[5m])))`                    | < 5 s   | End-to-end p99 lag from publish to consume. |
| `agent_decision_drift` | `sum(rate(agent_decision_override_total[5m])) / sum(rate(agent_decision_total[5m]))`                | < 0.05  | Decisions overridden by humans (proxy for AI risk). |

---

## 9. Error Budget Policy (Cross-Service)

The error budget is the amount of unreliability allowed by an SLO. We follow these rules uniformly:

1. **Burn-rate alert fires (page):** the on-call engineer has 30 minutes to acknowledge and begin mitigation. Burn rate is recomputed every minute.
2. **50% of monthly budget consumed:** the team's tech lead is notified; a post-incident review is scheduled within 5 business days.
3. **80% of monthly budget consumed:** non-critical feature work pauses for the owning team. Reliability work is prioritized.
4. **100% of monthly budget consumed (exhausted):** **deploy freeze** for the affected service(s). The freeze is lifted when the rolling window shows the budget replenished. A blameless review is held.
5. **Budget over-served (negative burn):** SRE proposes a tighter target at the next quarterly review.

The `service_error_budget_remaining` gauge is exported by every service:

```
service_error_budget_remaining_ratio{service="auth", slo="availability"} 0.62
```

A CI admission webhook refuses deploys when this value falls below 0.0 for any SLO of the service being deployed.

---

## 10. SLO Review Checklist (Quarterly)

For each SLO, the quarterly review answers:

- [ ] Is the target still aligned with user expectations?
- [ ] Is the window appropriate? (consider 7d, 30d, 90d)
- [ ] Are we still measuring the right thing?
- [ ] Has the budget been burned? Why?
- [ ] Are the burn alerts calibrated? (false positive rate < 5%)
- [ ] Are runbooks up to date?
- [ ] Are dashboards still useful?
- [ ] Has the cost of measurement stayed proportional to value?

---

*End of SLO & SLI Definitions v1.0*
