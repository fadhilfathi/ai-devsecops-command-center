# Runbook — CveFeedIntegrityRejected

> **Alert:** `CveFeedIntegrityRejected`
> **Source:** `infra/observability/prometheus/alert-rules.yml` (S2.8 control)
> **Severity:** **P2 (ticket)**
> **SLO target:** `devsecops_cve_feed_records_rejected_total{reason="integrity"}` rate < 0.1/s per feed over 5m
> **Threshold:** `sum by (feed) (rate(devsecops_cve_feed_records_rejected_total{reason="integrity"}[5m])) > 0.1` for 5m
> **Owner:** SREEngineer (SLO owner: VulnerabilityIntelligenceAgent — T-02 mitigation)
> **S2.8 control:** T-02 (CVE feed integrity)

## What this means

The CVE feed integrity gate in vuln-intel:4008 is rejecting records
from a feed at > 0.1/s for 5 minutes. The `reason="integrity"` reason
specifically means a cryptographic or signature check failed on the
incoming record. **Possible causes: feed compromise, upstream schema
change, or a broken verification key.**

## Triage

1. **Identify the feed:** the alert's `feed` label shows which feed
   is rejecting records (`nvd`, `ghsa`, `osv`).
2. **Check the feed status page / status endpoint:**
   - NVD: https://nvd.nist.gov/general/news
   - GHSA: https://github.com/advisories
   - OSV: https://osv.dev/
3. **Check the verification key rotation status:** if any of these
   feeds rotated their signing key recently, the gate may be
   rejecting records signed with the new key.
4. **Look at sample rejected records:**
   ```bash
   kubectl logs -l app=vuln-intel --tail=500 | grep 'integrity.rejected'
   ```
5. **Check if upstream changed the feed format:** schema changes
   can cause integrity failures if the verification hash is computed
   over the wire format.

## Common resolutions

- **Schema change:** update the gate to handle the new format; this
  is a code change, file a ticket against vuln-intel.
- **Key rotation:** update the verification key in the gate's config
  and reload.
- **Feed compromise:** **treat as P0**, not P2. Page security
  immediately. Stop ingesting from the affected feed until upstream
  confirms the feed is restored.

## Mitigation

- **Short-term:** if the rate is < 1/s, ingestion can continue
  with the failed records dropped (they don't propagate to the
  vulnerability database). If the rate is > 1/s, pause ingestion
  from the affected feed until the issue is resolved.
- **Long-term:** after the issue is resolved, do a backfill of any
  records that were dropped during the window (if upstream provides
  a delta endpoint).

## Related

- T-02 mitigation spec: `docs/architecture/s2-security-mitigations.md`
- `devsecops_cve_feed_records_rejected_total` metric: `docs/observability/metrics-spec.md` §3.10.3
- SLO doc: `docs/observability/slos-security-stack.md` §5.7
