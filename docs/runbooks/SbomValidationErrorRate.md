# Runbook — SbomValidationErrorRate

> **Alert:** `SbomValidationErrorRate`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (S2.8 control)
> **Severity:** **P3 (ticket)**
> **SLO target:** `devsecops_sbom_validation_errors_total` / `devsecops_proxy_request_total` < 1% over 5m
> **Threshold:** ratio > 0.01 for 5m
> **Owner:** SREEngineer (SLO owner: SecurityArchitect — T-08 mitigation)
> **S2.8 control:** T-08 (input validation)

## What this means

More than 1% of proxy requests to security-service :4003 are being
rejected for SBOM validation. The ratio is computed as
`sum(rate(devsecops_sbom_validation_errors_total[5m])) / sum(rate(devsecops_proxy_request_total[5m]))`.
**Possible causes: client regression (a tenant pushed a bad SBOM
schema), an active attack pattern (someone is fuzzing the API with
malformed SBOMs), or a recent spec change in the validation code
that's rejecting previously-valid SBOMs.**

## Triage

1. **Check the breakdown of rejection codes:** the
   `devsecops_sbom_validation_errors_total{code}` label tells you
   which validation rule is firing:
   - `sbom.purl.invalid` — bad package URL format
   - `sbom.size.exceeded` — over the S2.8 5,000-component cap
   - `sbom.format.unsupported` — wrong SBOM format version
   - `sbom.signature.invalid` — bad Cosign signature (also fires
     T-04 CosignVerifySlow if signature fetch is slow)
   - `sbom.hash.mismatch` — attestation hash doesn't match
2. **Identify the affected tenant(s):** the proxy_request_total
   metric has a `tenant_id_hash` label. Cross-reference the error
   spike with a specific tenant's traffic.
3. **Check the validation code for recent changes:** `git log
   backend/services/security-service/src/validation/` should show
   any recent commits.
4. **Look for a coordinated spike across multiple rejection codes:**
   if multiple codes are spiking, it's likely a client regression
   or attack pattern. If only one code is spiking, it's likely a
   specific tenant's payload.

## Common resolutions

- **Client regression:** notify the affected tenant with the
  rejection code and the example payload.
- **Attack pattern:** if the rate is > 5% (10x the threshold),
  escalate to P2. Consider rate-limiting the offending tenant or
  source IP.
- **Validation code change:** roll back the change if the spike
  started after a deploy.

## Mitigation

- **Short-term:** none required (P3 ticket). The 1% threshold is
  well below the 100% failure point; the system continues to
  function for the 99% of requests that pass validation.
- **Long-term:** if a specific rejection code is consistently
  spiking, consider relaxing that rule (with security sign-off) or
  improving client documentation.

## Related

- T-08 mitigation spec: `docs/architecture/s2-security-mitigations.md`
- `devsecops_sbom_validation_errors_total` metric: `docs/observability/metrics-spec.md` §3.10.1
- SLO doc: `docs/observability/slos-security-stack.md` §5.7
