# Runbook — CanaryTestFailure

> **Alert:** `CanaryTestFailure`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (S2.8 control)
> **Severity:** **P0 (page)**
> **SLO target:** `devsecops_canary_test_failures_total` MUST stay 0
> **Threshold:** `increase(devsecops_canary_test_failures_total[1m]) > 0` for 1m
> **Owner:** SREEngineer (SLO owner: SecurityArchitect — T-09 mitigation)
> **S2.8 control:** T-09 (data-exfiltration canary)

## What this means

A data-exfiltration canary test failed. The canary is a synthetic
token planted in the system that should NEVER appear in egress traffic;
if it shows up in any monitored egress point, an exfiltration event is
in progress (or a test is misfiring). **Treat as a probable data
exfiltration event until proven otherwise.**

## Immediate actions (P0)

1. **Page the on-call security team AND the on-call SRE immediately**
   (PagerDuty / equivalent). This is a P0.
2. **Open a P0 incident** with an incident commander. **Do not delay
   the page; canary failures are time-sensitive.**
3. **Identify the egress path:** the alert's `endpoint` label shows
   where the canary was observed. Check egress logs (VPC flow logs,
   Envoy access logs, NAT gateway logs) for the canary token.
4. **Network isolation:** consider pulling the affected service from
   the load balancer. Coordinate with the on-call SRE lead before
   pulling.
5. **Capture forensic state:** snapshot the affected service's
   process memory and recent network connections.
6. **Engage the security incident response team** per the runbook
   `docs/runbooks/security-incident-response.md` (T-09 escalation).

## False-positive triage

The canary is robust against false positives, but the alert can fire
in 3 known-benign cases:

1. **Canary test run during a release window.** Check the deploy log
   for a recent security-service deploy within the last 5 minutes.
2. **Canary test failure during a chaos engineering drill.** Check
   the chaos engineering calendar; if a drill is in progress, the
   alert is expected and the incident can be downgraded.
3. **Canary token leaked into a public dataset (test fixture, doc,
   log line).** Search the codebase for the canary string; if it's
   in a test fixture or public docs, the alert is a leak (still
   worth investigating but not a live exfiltration).

If none of the above match, treat as a live exfiltration event.

## Mitigation

- **Short-term:** isolate the affected service. Rotate credentials
  that may have been exposed.
- **Long-term:** after the incident is contained, do a postmortem
  to identify the exfiltration path and close it.

## Related

- T-09 mitigation spec: `docs/architecture/s2-security-mitigations.md`
- `devsecops_canary_test_failures_total` metric: `docs/observability/metrics-spec.md` §3.10.5
- SLO doc: `docs/observability/slos-security-stack.md` §5.7
- Security incident response runbook: `docs/runbooks/security-incident-response.md`
