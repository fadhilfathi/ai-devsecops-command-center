# Runbook — CosignVerifySlow

> **Alert:** `CosignVerifySlow`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (S2.8 control)
> **Severity:** **P3 (ticket)**
> **SLO target:** `devsecops_cosign_verify_duration_seconds{result="success"}` p95 < 30s over 5m
> **Threshold:** `histogram_quantile(0.95, ...) > 30` for 10m
> **Owner:** SREEngineer (SLO owner: SecurityArchitect — T-04 mitigation)
> **S2.8 control:** T-04 (supply-chain verification)

## What this means

Cosign/Rekor supply-chain verification on sbom-pipeline:4007 initContainer
is slow. p95 latency is over 30 seconds for 10 minutes. Cosign
verification is performed in the initContainer before the SBOM is
generated, so slow verification blocks the SBOM generation pipeline.
**Possible causes: Rekor transparency log degradation, Cosign service
latency, network issues reaching the Sigstore, or an oversized
attestation.**

## Triage

1. **Check Sigstore / Rekor status:**
   - https://status.sigstore.dev/
   - https://rekor.tlog.dev/ (the public Rekor instance)
2. **Check sbom-pipeline :4007 initContainer logs:**
   ```bash
   kubectl logs -l app=sbom-pipeline -c cosign-verify --tail=200
   ```
3. **Look at the verification duration breakdown:** the histogram
   in Grafana → Security Stack → Cosign Verify panel shows whether
   the slow path is signature fetch, Rekor inclusion proof, or
   certificate chain validation.
4. **Check network egress to Sigstore:**
   ```bash
   kubectl exec -it deploy/sbom-pipeline -c cosign-verify -- \
     curl -w '%{time_total}\n' -o /dev/null -s https://rekor.tlog.dev/api/v1/log
   ```
5. **Check attestation size:** if the SBOM has grown substantially,
   the attestation payload may have grown with it. Large attestations
   take longer to verify.

## Common resolutions

- **Rekor service degradation:** wait for upstream recovery; this is
  the most common cause. If the slowdown persists > 1h, consider
  switching to a Rekor mirror.
- **Network latency:** check egress connectivity; consider a regional
  Sigstore mirror for production deployments.
- **Oversized attestation:** investigate whether the SBOM can be
  reduced (e.g. drop dev dependencies from the attestation).
- **Cosign key rotation:** if Cosign rotated a root certificate
  recently, the old certificate chain may be slower to validate.

## Mitigation

- **Short-term:** none required (P3 ticket). The SBOM pipeline will
  continue to function, just slower.
- **Long-term:** if the slowdown is persistent, consider deploying
  a local Rekor mirror to reduce latency. Document the change in
  `docs/architecture/supply-chain.md`.

## Related

- T-04 mitigation spec: `docs/architecture/s2-security-mitigations.md`
- `devsecops_cosign_verify_duration_seconds` metric: `docs/observability/metrics-spec.md` §3.10.2
- SLO doc: `docs/observability/slos-security-stack.md` §5.7
