# Runbook — RiskScoreAuditChainBroken

> **Alert:** `RiskScoreAuditChainBroken`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (S2.8 control)
> **Severity:** **P0 (page)**
> **SLO target:** `devsecops_risk_score_audit_chain_verified{ok=1}` MUST equal fleet service count (i.e. `ok=0` count MUST be 0)
> **Threshold:** `sum by (service)(...{ok="0"}) > 0` for 1m
> **Owner:** SREEngineer (SLO owner: SecurityArchitect — T-05 mitigation)
> **S2.8 control:** T-05 (tamper detection)

## What this means

At least one service has `ok=0` for the risk-score audit chain
verification. **This is a tamper-detection signal** — the audit chain
that links risk-score calculations to their inputs (SBOM, vuln feed,
graph state) cannot be cryptographically verified on this service.
Possible causes: file system corruption, intentional tampering, broken
verification key, or a key rotation that wasn't propagated.

## Immediate actions (P0)

1. **Page the on-call security team immediately** (PagerDuty /
   equivalent). This is a P0.
2. **Snapshot the audit chain state** on the affected service(s):
   ```bash
   kubectl exec -it deploy/security-service -- \
     sh -c 'cat /var/lib/security/audit-chain/* > /tmp/chain-snapshot-$(date +%s).json'
   ```
3. **Check key rotation status:**
   ```bash
   kubectl exec -it deploy/security-service -- \
     env | grep -E 'AUDIT_KEY|AUDIT_CHAIN'
   ```
4. **Identify the affected service(s):** the alert's `service` label
   shows which service failed verification.
5. **Do NOT restart the service** — restarting may erase forensic state.
6. **Open an incident** and assign an incident commander. T-05 events
   are reportable to compliance (SOC 2 / ISO 27001 control failure).

## Investigation

- Check the audit-chain verification logs in Grafana → Security Stack
  → Audit Chain panel.
- Compare the current chain hash against the last good known hash.
- If the chain is broken at a recent point, identify the operation
  that broke it (which risk score, which input, which user/tenant).
- Cross-reference with the access logs for the audit chain store
  during the same window.

## Mitigation

- **Short-term:** freeze risk-score writes on the affected service
  until verification is restored. New risk scores are emitted with
  `ok=0` until cleared.
- **Long-term:** re-verify the chain from the last good snapshot;
  either restore the chain or rebuild from a known-good backup.

## Related

- T-05 mitigation spec: `docs/architecture/s2-security-mitigations.md`
- `devsecops_risk_score_audit_chain_verified` metric: `docs/observability/metrics-spec.md` §3.10.4
- SLO doc: `docs/observability/slos-security-stack.md` §5.7
