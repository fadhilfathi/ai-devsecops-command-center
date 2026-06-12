# vuln-intel — Vulnerability Intelligence Service (S2.2)

> CVE ingestion, normalization, severity scoring, and EPSS-based exploit
> likelihood. FastAPI service, port **4008**.

## Responsibilities

| Capability | Source |
|---|---|
| CVE ingestion (full text + delta) | NVD 2.0 (`/rest/json/cves/2.0`) |
| CVE ingestion (security advisories) | GitHub Advisory DB (`/advisories`) |
| CVE ingestion (cross-ecosystem)    | OSV.dev (`/v1/query` + `/v1/vulns/{id}`) |
| Exploit likelihood                  | FIRST.org EPSS (`/api/v1/epss`) |
| KEV (known exploited)               | CISA KEV (`/known_exploited_vulnerabilities.json`) |
| Severity scoring                    | CVSS 3.1 / 4.0 (derived from source) |
| Local store (cross-restart)         | JSONL append-only feed (simple, versioned) |
| Cache                               | TTL in-process (cachetools) + Redis optional |

## Data model

Unified `CveRecord`:

```
CveRecord {
  id: "CVE-2024-31337"   // primary key
  aliases: ["GHSA-xxxx", "PYSEC-2024-..."]   // alternate IDs
  source: ["nvd", "ghsa", "osv"]
  published: ISO-8601
  modified:  ISO-8601
  summary: str
  details:  str
  severity: { cvss_v3: { score, vector, severity }, cvss_v4: {...} | null, qualitative: "CRITICAL" }
  epss:     { score: 0..1, percentile: 0..1, fetched_at: ISO-8601 } | null
  kev:      { exploited: bool, date_added?: ISO, due_date?: ISO } | null
  affected: [{ purl?, ecosystem, name, versions: [{ introduced?, fixed?, last_affected? }] }]
  references: [{ url, type, tags }]
  cwes: [int]
  raw: { nvd?, ghsa?, osv? }   // kept for traceability
}
```

The full Pydantic schema lives in
`src/vuln_intel/models/cve.py`. The schema is intentionally aligned with
the public CVE 5.0 record (`cve.org`) where possible so that downstream
consumers (compliance, risk layer) don't have to relearn the field names.

## Endpoints (REST, JSON)

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/livez`                              | Liveness — process is up |
| `GET`  | `/readyz`                             | Readiness — sources reachable, store writable |
| `GET`  | `/metrics`                            | Prometheus text format |
| `POST` | `/vuln-intel/ingest`                  | Trigger ad-hoc ingestion (all or one source) |
| `GET`  | `/vuln-intel/cve/{cve_id}`            | Fetch a single normalized CVE |
| `POST` | `/vuln-intel/cve/lookup`              | Bulk lookup by `CVE-…`, `GHSA-…`, `PYSEC-…` |
| `POST` | `/vuln-intel/score`                   | Compute / refresh severity + EPSS for one or many CVEs |
| `POST` | `/vuln-intel/match`                   | Match vulnerabilities to a list of SBOM components |
| `GET`  | `/vuln-intel/stats`                   | Coverage / cache stats |
| `POST` | `/vuln-intel/sync/once`               | Manual one-shot NVD + GHSA + OSV + EPSS pull |

## Configuration (env vars)

| Var | Default | Notes |
|---|---|---|
| `VULN_INTEL_PORT` | `4008` | API port |
| `VULN_INTEL_TENANT_ID` | `default` | Tenant ID for single-tenant mode |
| `VULN_INTEL_DATA_DIR`  | `./data` | Where the JSONL store is kept |
| `NVD_API_KEY`          | unset    | 5 req/30s without key, 50 req/30s with key |
| `GITHUB_TOKEN`         | unset    | 60 req/h unauthenticated, 5000 req/h authed |
| `EPSS_CACHE_TTL`       | `3600`   | seconds |
| `NVD_CACHE_TTL`        | `86400`  | seconds |
| `OSV_CACHE_TTL`        | `86400`  | seconds |
| `INGEST_SCHEDULE`      | `0 3 * * *` | when in cron mode (daily 03:00 UTC) |
| `LOG_LEVEL`            | `INFO`  | DEBUG / INFO / WARNING / ERROR |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTel collector |

## Local dev

```bash
cd agents/roles/security/vuln-intel
pip install -e ".[dev]"
VULN_INTEL_PORT=4008 python -m vuln_intel
```

## Source provenance & licensing

- NVD data is public domain (NIST).
- GitHub Advisories are CC-BY-4.0 (GitHub).
- OSV.dev data is CC-BY-4.0 (Google).
- EPSS data is CC-BY-4.0 (FIRST.org).
- CISA KEV is public domain (US Government).

All sources are attributable from the `source` and `raw` fields of the
stored record.
