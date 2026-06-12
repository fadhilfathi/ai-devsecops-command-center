# Runbook — LlmTokenBudgetLow

> **Alert:** `LlmTokenBudgetLow`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (S2.8 control)
> **Severity:** **P3 (ticket)**
> **SLO target:** `devsecops_llm_token_budget_remaining` ≥ 20% (i.e. budget is 80% consumed)
> **Threshold:** gauge < 0.20 for 5m
> **Owner:** SREEngineer (SLO owner: VulnerabilityIntelligenceAgent — T-03 mitigation)
> **S2.8 control:** T-03 (LLM cost guardrail)

## What this means

The LLM token budget for vuln-intel:4008 CVE summarization is below
20% remaining. The gauge represents the fraction of the monthly/daily
budget still available (1.0 = full budget, 0.0 = empty). The LLM-driven
CVE summarization will throttle or stop when the budget reaches 0.

**Possible causes: high CVE publication rate, an over-eager
summarization policy, a budget misconfiguration, or an LLM call loop.**

## Triage

1. **Check the LLM call volume:** Grafana → Security Stack → LLM
   Calls panel. Is the volume abnormally high?
2. **Check the summarization policy:** is it summarizing more CVEs
   than expected? Are there any new tenants with high-summarization
   settings?
3. **Check for LLM call loops:** if a summarization fails and is
   retried, it can consume budget rapidly. Look for repeated calls
   in the LLM call log.
4. **Compare to historical budget burn rate:** the gauge should be
   tracked over time; a sudden drop suggests an unusual event.

## Common resolutions

- **High CVE publication rate:** wait for the rate to subside; this
  is the most common cause.
- **Over-eager summarization policy:** tune the policy to summarize
  only Critical/High CVEs (drop Medium/Low).
- **Budget misconfiguration:** verify the budget is set to the
  expected monthly/daily value.
- **LLM call loop:** find the loop in the call log and fix the
  retry logic.

## Mitigation

- **Short-term:** none required (P3 ticket). The system will
  gracefully degrade (LLM summarization will throttle or stop) once
  the budget reaches 0.
- **Long-term:** if the budget is consistently exhausted before
  the cycle ends, request a budget increase from finance. Document
  the request in `docs/architecture/llm-budget-tracking.md`.

## Related

- T-03 mitigation spec: `docs/architecture/s2-security-mitigations.md`
- `devsecops_llm_token_budget_remaining` metric: `docs/observability/metrics-spec.md` §3.10.6
- SLO doc: `docs/observability/slos-security-stack.md` §5.7
