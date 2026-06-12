# Alerting Rules & Runbooks

> **Sprint:** 1 — Foundations
> **Owner:** SREEngineer
> **Status:** Draft v1.0
> **Last Updated:** 2026-06-12
> **Companion doc:** [`monitoring-architecture.md`](./monitoring-architecture.md), [`slo-sli-definitions.md`](./slo-sli-definitions.md)

This document specifies the **standard alert rules** every service inherits, the **SLO burn-rate templates**, and the **runbook** that on-call engineers follow when an alert fires. Every alert rule must reference a runbook section by ID; missing runbooks are rejected by the lint.

---

## 1. Standard (Service-Agnostic) Alert Rules

These rules apply to every backend service. The `service` label is set by the Prometheus relabeling rules in `infra/observability/prometheus/relabel.yml`.

### 1.1 `ServiceDown`

- **Expression:**
  ```promql
  up{service=~"$service"} == 0
  ```
- **For:** 2m
- **Severity:** page
- **Runbook:** [§6.1](#61-servicedown)
- **Why:** The scrape has failed for 2 consecutive minutes.

### 1.2 `ServiceCrashLooping`

- **Expression:**
  ```promql
  increase(kube_pod_container_status_restarts_total{service=~"$service"}[15m]) > 3
  ```
- **For:** 0m
- **Severity:** page
- **Runbook:** [§6.2](#62-servicecrashlooping)
- **Why:** 3+ restarts in 15m is a crash loop, not a transient blip.

### 1.3 `ServiceHigh5xxRate`

- **Expression:**
  ```promql
  sum by (service, route) (rate(http_requests_total{service=~"$service",status=~"5.."}[5m]))
    / sum by (service, route) (rate(http_requests_total{service=~"$service"}[5m]))
    > 0.05
  ```
- **For:** 5m
- **Severity:** page
- **Runbook:** [§6.3](#63-servicehigh5xxrate)
- **Why:** More than 5% of requests failing for 5 consecutive minutes.

### 1.4 `ServiceHighP99Latency`

- **Expression:**
  ```promql
  histogram_quantile(0.99,
    sum by (le, service, route) (rate(http_request_duration_seconds_bucket{service=~"$service"}[5m]))
  ) > 1
  ```
- **For:** 10m
- **Severity:** ticket
- **Runbook:** [§6.4](#64-servicehighp99latency)
- **Why:** p99 latency over 1s sustained 10m is a degradation.

### 1.5 `ServiceErrorBudgetExhausted`

- **Expression:**
  ```promql
  service_error_budget_remaining_ratio{service=~"$service"} < 0
  ```
- **For:** 1m
- **Severity:** page
- **Runbook:** [§6.5](#65-serviceerrorbudgetexhausted)
- **Why:** Service can no longer afford additional unreliability; deploys halt.

### 1.6 `ServiceDeepHealthCheckFailing`

- **Expression:**
  ```promql
  probe_success{job="readyz", service=~"$service"} == 0
  ```
- **For:** 3m
- **Severity:** page
- **Runbook:** [§6.6](#66-servicedeephealthcheckfailing)
- **Why:** Service is up but `/readyz` is failing — likely a downstream dependency is broken.

### 1.7 `ServiceCardinalityExplosion`

- **Expression:**
  ```promql
  deriv(prometheus_tsdb_head_series{service=~"$service"}[10m]) > 100000
  ```
- **For:** 5m
- **Severity:** ticket
- **Runbook:** [§6.7](#67-servicecardinalityexplosion)
- **Why:** Series count growing > 100k/min signals a label-explosion bug.

### 1.8 `WatchdogDeadmanSwitch`

- **Expression:**
  ```promql
  vector(time() - prometheus_last_evaluation_timestamp) > 300
  ```
- **For:** 0m
- **Severity:** page
- **Runbook:** [§6.8](#68-watchdogdeadmanswitch)
- **Why:** Prometheus itself is broken or stuck. Always fires — never silence.

---

## 2. Agent-Specific Alert Rules

### 2.1 `AgentTaskFailureRate`

- **Expression:**
  ```promql
  sum by (agent, task_type) (rate(agent_tasks_total{outcome="failure"}[5m]))
    / sum by (agent, task_type) (rate(agent_tasks_total[5m]))
    > 0.10
  ```
- **For:** 10m
- **Severity:** ticket
- **Runbook:** [§7.1](#71-agenttaskfailurerate)

### 2.2 `AgentTaskDurationP99High`

- **Expression:**
  ```promql
  histogram_quantile(0.99,
    sum by (le, agent, task_type) (rate(agent_task_duration_seconds_bucket[10m]))
  ) > 300
  ```
- **For:** 15m
- **Severity:** ticket
- **Runbook:** [§7.2](#72-agenttaskdurationp99high)
- **Why:** p99 task > 5 min sustained 15m.

### 2.3 `AgentLLMTokenSpendAnomaly`

- **Expression:**
  ```promql
  sum by (agent, model) (rate(agent_llm_tokens_total[1h]))
    > 3 * avg_over_time(sum by (agent, model) (rate(agent_llm_tokens_total[1h]))[7d:1h])
  ```
- **For:** 30m
- **Severity:** ticket
- **Runbook:** [§7.3](#73-agentllmtokenspendanomaly)
- **Why:** 3× the rolling-7d average hourly spend.

### 2.4 `AgentDecisionOverride`

- **Expression:**
  ```promql
  sum(rate(agent_decision_override_total[5m]))
    / sum(rate(agent_decision_total[5m]))
    > 0.20
  ```
- **For:** 10m
- **Severity:** ticket
- **Runbook:** [§7.4](#74-agentdecisionoverride)
- **Why:** More than 20% of agent decisions being overridden by humans suggests model drift.

---

## 3. SLO Burn-Rate Alert Templates

These templates are rendered per SLO from the SLO catalog. The variable `{{slo}}` is replaced with the SLO name and `{{target}}` with its target.

### 3.1 Fast-Burn (Page)

For a target `T` over window `W` (default 30d = 43,200 min), the **fast-burn** window is `W / 6` and the threshold is `2 * (1 - T) * 6`.

```promql
(
  sum(sli_query) > (1 - {{target}}) * 2
  and
  sum(sli_query) > (1 - {{target}}) * 2
)
```

Concretely, for a 99.9% SLO:

```promql
(
  sum(rate(http_requests_total{service="auth",status!~"5.."}[1h]))
    / sum(rate(http_requests_total{service="auth"}[1h]))
    < (1 - (1 - 0.999))
  and
  sum(rate(http_requests_total{service="auth",status!~"5.."}[6h]))
    / sum(rate(http_requests_total{service="auth"}[6h]))
    < (1 - (1 - 0.999))
)
```

- **For:** 2m (1h) and 5m (6h)
- **Severity:** page
- **Runbook:** [§8](#8-slo-burn-incident-runbook)

### 3.2 Slow-Burn (Ticket)

```promql
(
  sum(rate(http_requests_total{service="auth",status!~"5.."}[24h]))
    / sum(rate(http_requests_total{service="auth"}[24h]))
    < (1 - (1 - 0.999))
  and
  sum(rate(http_requests_total{service="auth",status!~"5.."}[3d]))
    / sum(rate(http_requests_total{service="auth"}[3d]))
    < (1 - (1 - 0.999))
)
```

- **For:** 30m (24h) and 2h (3d)
- **Severity:** ticket
- **Runbook:** [§8](#8-slo-burn-incident-runbook)

The full template generator lives at `infra/observability/prometheus/templates/slo-burn.yml.j2`.

---

## 4. Alert Annotations

Every alert includes a templated `description`, `summary`, and links. Example:

```yaml
annotations:
  summary: "Auth service 5xx rate elevated"
  description: |
    Service `auth` is returning 5xx for {{ $value | humanizePercentage }} of requests
    over the last 5 minutes. SLO `availability` budget remaining: {{ with query "service_error_budget_remaining_ratio{service='auth',slo='availability'}" }}{{ . | first | value | humanizePercentage }}{{ end }}.
  dashboard: "https://grafana.example.com/d/auth-overview"
  runbook: "https://runbooks.example.com/auth/ServiceHigh5xxRate"
  slo: "auth/availability"
  team: "platform-identity"
```

The linter rejects alerts without a `runbook` URL.

---

## 5. Routing

`infra/observability/alertmanager/alertmanager.yml`:

```yaml
route:
  receiver: default
  group_by: [alertname, service, severity]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - matchers: [severity="page"]
      receiver: pagerduty
      group_wait: 10s
      repeat_interval: 1h
    - matchers: [severity="ticket"]
      receiver: github-issues
      group_wait: 1m
      repeat_interval: 24h
    - matchers: [severity="info"]
      receiver: slack-info
      group_wait: 1m
      repeat_interval: 24h

receivers:
  - name: default
    webhook_configs:
      - url: http://event-bus:8080/alerts
  - name: pagerduty
    pagerduty_configs:
      - service_key: <vault:pagerduty/key>
        severity: critical
  - name: github-issues
    webhook_configs:
      - url: http://integration:8080/issue/create
  - name: slack-info
    slack_configs:
      - channel: "#sre-info"
        send_resolved: true
```

---

## 6. Service Alert Runbooks

### 6.1 `ServiceDown`

**Owner:** On-call SRE
**Goal:** Restore service availability within SLO budget.

1. Open the service dashboard; confirm the `up == 0` alert.
2. Check `kubectl get pods -l service=<service>` for crash / OOM / pending.
3. Tail recent error logs in Grafana Explore filtered by `service=<service>` and `level=error`.
4. If pods are running but not ready, jump to [§6.6](#66-servicedeephealthcheckfailing).
5. If the issue is a bad deploy, **roll back** via the GitOps controller.
6. If unknown, capture process state (`kubectl describe`, `kubectl get events`) and escalate to the service owner.

### 6.2 `ServiceCrashLooping`

1. `kubectl logs -l service=<service> --previous --tail=200`.
2. Identify the exception class. Common: OOMKilled, NullPointer, config parse error.
3. If OOMKilled: check `container_memory_working_set_bytes` vs the limit; raise limit or fix leak.
4. If config error: roll back.
5. If null-deref or panic: capture stack, file a Sev1, engage the service owner.

### 6.3 `ServiceHigh5xxRate`

1. Drill into the dashboard: which route(s) are failing?
2. Inspect logs for the failing route. Look for upstream errors, DB errors, auth errors.
3. Check dependency health (DB, Redis, NATS, external API).
4. If a dependency is down, jump to that service's runbook and consider degrading this service.
5. If a recent deploy correlates, roll back.

### 6.4 `ServiceHighP99Latency`

1. Identify the slow route from the panel.
2. Inspect spans in Tempo for p99 of that route. Look for slow dependencies.
3. Check DB query times (`db.client.duration`).
4. Check event loop lag (`nodejs_eventloop_lag_seconds`) and GC (`go_gc_duration_seconds`).
5. If a dependency is slow, open a ticket with the dependency owner.

### 6.5 `ServiceErrorBudgetExhausted`

1. **Stop all non-critical deploys** to the affected service.
2. Identify the SLO that is exhausted and the active burn alert.
3. Open the burn dashboard; identify the worst-affected routes / operations.
4. Engage the service owner and the SRE lead.
5. After stabilization, schedule a blameless review and consider a tighter SLO target.

### 6.6 `ServiceDeepHealthCheckFailing`

1. The process is up but a dependency check inside `/readyz` is failing.
2. Open the `/readyz` payload (Grafana Explore, JSON datasource).
3. Identify which dependency is failing. Jump to its runbook.
4. If the failing dependency is a vendor, consider flipping the circuit breaker to "open" in the dynamic config to fail fast.
5. Once the dependency recovers, watch the readiness probe recover; if it doesn't, restart the pods.

### 6.7 `ServiceCardinalityExplosion`

1. Inspect `prometheus_tsdb_head_series` per job.
2. Use the cardinality inspector (`/api/v1/status/tsdb`) to list top-50 label combinations.
3. Common culprits: including `user_id`, `email`, `request_id` in metric labels.
4. Roll back the offending PR or add a `metric_relabel_configs` drop rule.
5. If emergency, drop the metric with a hot-fix relabel rule and file a follow-up.

### 6.8 `WatchdogDeadmanSwitch`

1. This alert is **always live**; never silence.
2. If it fires, Prometheus itself is unhealthy. Check the Prometheus pods.
3. Failover to the HA replica (`prometheus-1` ↔ `prometheus-2`).
4. Restore the primary from the operator runbook.

---

## 7. Agent Alert Runbooks

### 7.1 `AgentTaskFailureRate`

1. Drill into the failing agent and task type.
2. Inspect agent logs and traces in Grafana.
3. Common causes: tool timeout, LLM provider 5xx, schema validation error.
4. If LLM provider: check the `agent_llm_tokens_total` and provider status page; consider model fallback.
5. If tool: jump to the tool's service runbook.

### 7.2 `AgentTaskDurationP99High`

1. Inspect p99 task duration in the agent dashboard.
2. Compare to LLM provider latency; if correlated, file with the provider.
3. Check `agent_tasks_in_flight` for queue saturation; scale the worker pool.
4. If a specific task type is slow, examine spans for repeated retries.

### 7.3 `AgentLLMTokenSpendAnomaly`

1. Compare to the rolling 7-day baseline.
2. Identify the model and agent driving the spike.
3. Check for runaway loops (recurring `agent_task_duration_seconds` over budget).
4. Lower `max_tokens` or `max_steps` for the affected agent via dynamic config.
5. Open a FinOps ticket; consider rate-limiting.

### 7.4 `AgentDecisionOverride`

1. Pull the override reasons from `agent_decision_override_total{reason=...}`.
2. The top reasons usually map to a prompt regression or training-data drift.
3. Open a Sev2 to the AI team to evaluate.
4. Consider downgrading the affected agent to "suggest" mode (human-in-the-loop) until retrained.

---

## 8. SLO Burn Incident Runbook

**Applies to:** All burn-rate alerts (page and ticket).

1. **Acknowledge** within 5 minutes.
2. **Identify the SLO and the burn window.** The alert annotation names both.
3. **Check the budget gauge.** How much budget remains?
4. **Find the dominant contributor.** Use the burn breakdown panel (per route, per error class).
5. **Mitigate:** roll back, fail open, scale, rate-limit — whatever restores SLO fastest.
6. **Communicate:** post a status page update if user-impacting.
7. **Stabilize:** watch the burn rate drop. Don't close the incident until burn rate is below 1× for at least 1h.
8. **Review:** within 5 business days, blameless post-mortem with action items and a target date for SLO recovery.

---

*End of Alerting Rules & Runbooks v1.0*
