# Security Service

Vulnerability scanning, SBOM management, finding aggregation, and the
**S2.5 security API layer** that proxies to the Python agent fleet and
serves the security dashboard.

- Port: **4003** (Sprint 2)
- Sprint 1 surface: `/v1/assets`, `/v1/scans`, `/v1/findings`, `/v1/sboms`
- **Sprint 2 (new):** `POST /sbom/generate`, `POST /sbom/analyze`,
  `POST /vulnerabilities/ingest`, `POST /risk/calculate`, `GET /security/dashboard`
- OpenAPI / Swagger at **`/docs`**
- Per-route rate limit: **10 req/s** (`@fastify/rate-limit`)
- Auth: HS256 JWT (Sprint 2 stub); RS256 via `@aicc/auth` in Sprint 2.1
- RBAC: `platform_admin` or `security_engineer` for POSTs;
  any authenticated role for GETs (incl. dashboard)

## Architecture (S2.5)

```
HTTP client
  │
  ▼
┌─────────────────────────┐
│   security-service      │  (this service, port 4003)
│   ┌──────────────────┐  │
│   │ /sbom/generate   │──┼─HTTP──▶ sbom-pipeline-service   :4007  (Python)
│   │ /sbom/analyze    │──┼─HTTP──▶ sbom-pipeline-service   :4007  (Python)
│   │ /vulns/ingest    │──┼─HTTP──▶ vuln-intel-service      :4008  (Python)
│   │ /risk/calculate  │──┼─HTTP──▶ dependency-intel-service:4009  (Python)
│   │ /security/dash   │  │  ──▶ local aggregate (in-memory)
│   └──────────────────┘  │
│   OpenAPI: /docs        │
│   Metrics: /metrics     │
│   Health: /healthz      │
└─────────────────────────┘
        │
        ▼
  Redis Streams (event bus)
   - security.sbom.generated
   - security.vulnerability.detected
   - security.risk.calculated
```

## Observability (S2.7)

Prometheus metrics for the security-service :4003 proxy layer. The service
exposes a Prometheus scrape endpoint at **`GET /metrics`** (content type
`text/plain; version=0.0.4`) and emits **6 custom metrics** in addition to
the default Node.js process metrics (prefixed `devsecops_node_`).

### Metrics owned by security-service :4003

All metrics follow `devsecops_{domain}_{noun}_{unit_suffix}` per
PlatformArchitect Decision #11 (locked by SRE 2026-06-12). Cardinality is
bounded by #tenants × #routes × #targets; well under the 50k-series
per-service budget for the expected Sprint 2 scale (≤50 tenants).

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `devsecops_proxy_request_duration_seconds` | Histogram | `service`, `route`, `target_service`, `result` | security-service → Python service proxy hop latency |
| `devsecops_proxy_request_total` | Counter | `service`, `route`, `target_service`, `status_code` | All proxy requests (success + 4xx + 5xx + timeout) |
| `devsecops_eventbus_publish_total` | Counter | `service`, `topic`, `result` | Event-bus publish attempts (`success` \| `error`) |
| `devsecops_rate_limit_triggered_total` | Counter | `service`, `route` | 429 responses from per-route/global rate limiting |
| `devsecops_auth_failure_total` | Counter | `service`, `route`, `reason` | Auth/authz failures (`reason` = `missing_token` \| `invalid_signature` \| `expired` \| `forbidden_role` \| `tenant_mismatch`) |
| `devsecops_dashboard_query_duration_seconds` | Histogram | `service`, `endpoint` | GET /security/dashboard aggregation latency |

**Ownership map (S2.7 locked):** security-service :4003 owns these 6
metrics. The 3 Python services own their own metrics
(`devsecops_sbom_generation_duration_seconds`, etc.) and the
platform-wide `devsecops_eventbus_lag_seconds` (PlatformArchitect SLI).

**Service label:** the `service` label is auto-injected by the
`@aicc/observability` helper (from `OTEL_SERVICE_NAME`, fallback
`'unknown'`) per `docs/observability/metrics-spec.md` §5.1.1. Consumers
do not need to supply it; the helper prepends it on every `inc()` /
`observe()` call via `withService({ ... })`.

**No `tenant_id`-style labels:** per `metrics-spec.md` §5.1, high-cardinality
or PII labels (`tenant_id`, `user_id`, `request_id`, `agent_id`, `worker_id`,
`trace_id`, and any form of them) are **forbidden on metrics**. Use logs
(the standard logger requires `tenant_id`) for per-tenant forensics, and
tracing (OTel `trace_id` / `span_id` are natural there) for request flow.
The `@aicc/observability` helper exports `assertNoForbiddenLabels()` to
catch violations at metric-construction time.

### Scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: aicc-security-service
    metrics_path: /metrics
    scrape_interval: 15s
    static_configs:
      - targets: ['security-service:4003']
```

### Useful queries (PromQL)

```promql
# 99th-percentile proxy latency per route+target (SLO)
histogram_quantile(0.99, sum by (le, route, target_service) (rate(devsecops_proxy_request_duration_seconds_bucket[5m])))

# Error rate (4xx + 5xx + timeouts) by route
sum by (route) (rate(devsecops_proxy_request_total{status_code!~"2.."}[5m]))
  / sum by (route) (rate(devsecops_proxy_request_total[5m]))

# Auth failure rate by reason
sum by (reason) (rate(devsecops_auth_failure_total[5m]))

# Top-N tenants triggering rate limits (security forensics)
# Top-N tenants triggering rate limits (security forensics — NOTE: tenant_id
# is forbidden on metrics, so aggregate from logs instead, e.g. Loki/Grafana
# on the `tenant_id` field, or use a recording rule over the auth_failure
# series if you need rate-limit correlation).
# topk(10, sum by (tenant_id) (rate({kind="rate_limit_triggered"} | json | __error__="" [5m])))
```

## Endpoints (S2.5)

All endpoints require `Authorization: Bearer <JWT>` unless noted.
Tenant scoping is enforced via JWT claim (`tenantId`) and the
`requireTenantMatch` middleware (rejects mismatches with `x-tenant-id`).

### `POST /sbom/generate`

Generate an SBOM from a container image, git repo, or filesystem path.
Proxies to `sbom-pipeline-service` (port 4007).

**RBAC:** `platform_admin`, `security_engineer`
**Rate limit:** 10 req/s

**Request body** (`SbomGenerateRequest` from `@aicc/shared/security`):

```json
{
  "source": { "kind": "container", "image": "nginx:1.25-alpine" },
  "transitive": true,
  "format": "cyclonedx",
  "specVersion": "1.5"
}
```

**Example:**

```bash
curl -sS -X POST http://localhost:4003/sbom/generate \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "source": { "kind": "container", "image": "nginx:1.25-alpine" },
    "transitive": true
  }'
```

**Response 200** (`SbomServiceResponse`):

```json
{
  "jobId": "11111111-1111-4111-8111-111111111111",
  "status": "succeeded",
  "startedAt": "2025-01-15T10:00:00.000Z",
  "finishedAt": "2025-01-15T10:00:42.000Z",
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "serialNumber": "urn:uuid:22222222-2222-4222-8222-222222222222",
    "metadata": { "timestamp": "2025-01-15T10:00:42.000Z" },
    "components": [ /* … */ ],
    "dependencies": [ /* … */ ]
  }
}
```

**Event emitted:** `security.sbom.generated` on the event bus.

---

### `POST /sbom/analyze`

Analyse an existing SBOM for license compatibility and outdated deps.
Proxies to `sbom-pipeline-service` (port 4007).

**RBAC:** `platform_admin`, `security_engineer`
**Rate limit:** 10 req/s

**Request body** (`SbomAnalyzeRequest`):

```json
{
  "sbom": { /* Sbom object — same shape as /sbom/generate response */ },
  "outdated": true,
  "licenseMatrix": true
}
```

**Example:**

```bash
curl -sS -X POST http://localhost:4003/sbom/analyze \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "sbom": { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {} },
  "outdated": true,
  "licenseMatrix": true
}
JSON
```

**Response 200** (`SbomServiceResponse` with `report` populated).

---

### `POST /vulnerabilities/ingest`

Ingest vulnerabilities by id (CVE/GHSA/OSV) and normalise across sources.
Proxies to `vuln-intel-service` (port 4008).

**RBAC:** `platform_admin`, `security_engineer`
**Rate limit:** 10 req/s

**Request body** (`VulnerabilityIngestRequest`):

```json
{
  "ids": ["CVE-2021-44228", "CVE-2022-22965", "GHSA-jfh8-c2jp-5v3q"],
  "refreshEpss": true,
  "refreshKev": true
}
```

**Example:**

```bash
curl -sS -X POST http://localhost:4003/vulnerabilities/ingest \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "ids": ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
    "refreshEpss": true,
    "refreshKev": true
  }'
```

**Response 200** (`VulnerabilityIngestResponse`):

```json
{
  "jobId": "33333333-3333-4333-8333-333333333333",
  "status": "succeeded",
  "startedAt": "2025-01-15T10:01:00.000Z",
  "finishedAt": "2025-01-15T10:01:08.000Z",
  "ingested": [
    {
      "id": "CVE-2021-44228",
      "aliases": ["GHSA-jfh8-c2jp-5v3q"],
      "severity": "critical",
      "cvssV3": {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "baseScore": 10.0,
        "baseSeverity": "CRITICAL"
      },
      "kev": true,
      "affected": [
        {
          "package": { "name": "log4j-core", "ecosystem": "Maven" },
          "vulnerableRanges": [
            { "kind": "semver", "expression": ">=2.0, <2.15.0" }
          ]
        }
      ],
      "references": [ /* … */ ],
      "descriptions": [{ "lang": "en", "value": "Apache Log4j2 JNDI features…" }],
      "publishedAt": "2021-12-10T00:00:00.000Z",
      "lastModifiedAt": "2024-04-15T00:00:00.000Z",
      "source": "nvd"
    }
  ],
  "failed": []
}
```

**Events emitted:** one `security.vulnerability.detected` per ingested vuln.

---

### `POST /risk/calculate`

Compute the dependency risk graph + composite risk scores for an SBOM.
Proxies to `dependency-intel-service` (port 4009).

**RBAC:** `platform_admin`, `security_engineer`
**Rate limit:** 10 req/s

**Request body** (`RiskCalculateRequest`):

```json
{
  "sbom": { /* Sbom object */ },
  "vulnerabilities": [ /* Vulnerability[] from vuln-intel-service */ ],
  "factorWeights": {
    "severity": 0.35, "epss": 0.20, "kev": 0.20,
    "reachability": 0.15, "exposure": 0.10
  }
}
```

**Example:**

```bash
curl -sS -X POST http://localhost:4003/risk/calculate \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "sbom": { "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {} },
  "vulnerabilities": [],
  "factorWeights": {
    "severity": 0.35, "epss": 0.20, "kev": 0.20,
    "reachability": 0.15, "exposure": 0.10
  }
}
JSON
```

**Response 200** (`RiskCalculateResponse` with `graph` populated).

**Events emitted:** up to 5 `security.risk.calculated` (one per top-risk component).

---

### `GET /security/dashboard`

Aggregate security dashboard — SBOM count, vuln count by severity,
top 5 riskiest components, recent activity, security score + 7-day trend.

**RBAC:** any authenticated role
**Rate limit:** 10 req/s

**Query parameters:**

| Name       | Type   | Required | Description                                |
|------------|--------|----------|--------------------------------------------|
| `tenantId` | UUID   | no       | Defaults to the JWT `tenantId` claim       |

**Example:**

```bash
curl -sS http://localhost:4003/security/dashboard \
  -H "Authorization: Bearer $JWT"
```

**Response 200** (`SecurityDashboardResponse`):

```json
{
  "generatedAt": "2025-01-15T10:05:00.000Z",
  "tenantId": "00000000-0000-4000-8000-000000000000",
  "sbomCount": 42,
  "vulnCountBySeverity": {
    "critical": 3, "high": 12, "medium": 47,
    "low": 89, "info": 23, "unknown": 0
  },
  "totalVulnCount": 174,
  "topRiskyComponents": [
    {
      "bomRef": "pkg:log4j-core@2.14.1",
      "name": "log4j-core",
      "version": "2.14.1",
      "score": 92,
      "topVulnerabilityId": "CVE-2021-44228",
      "topCvssScore": 10.0,
      "kev": true
    }
  ],
  "recentActivity": [
    {
      "id": "44444444-4444-4444-8444-444444444444",
      "type": "vulnerability.detected",
      "timestamp": "2025-01-15T10:01:08.000Z",
      "summary": "Vulnerability CVE-2021-44228 (critical) detected",
      "severity": "critical"
    }
  ],
  "securityScore": 28,
  "securityScoreTrend": [
    { "date": "2025-01-09", "score": 30 },
    { "date": "2025-01-10", "score": 29 },
    { "date": "2025-01-11", "score": 31 },
    { "date": "2025-01-12", "score": 30 },
    { "date": "2025-01-13", "score": 28 },
    { "date": "2025-01-14", "score": 27 },
    { "date": "2025-01-15", "score": 28 }
  ],
  "modelVersion": "security-score-v1"
}
```

---

## Auth — issuing a dev token (S2.5 stub)

Until `@aicc/auth` lands in Sprint 2.1, generate a dev JWT inline with the
helper exported from `src/middleware/auth.ts`:

```ts
import { signDevJwt } from '@aicc/security-service/middleware/auth';

const token = signDevJwt({
  secret: 'change-me-in-production-please-use-a-long-random-string',
  issuer: 'aicc',
  audience: 'aicc-api',
  sub: 'admin-user-uuid',
  email: 'admin@aicc.local',
  role: 'security_engineer',
  tenantId: '00000000-0000-4000-8000-000000000000',
  ttlSeconds: 3600,
});
```

Or use the `auth-service`'s `POST /v1/auth/dev-login` from Sprint 1.

## Health

- `GET /healthz` — liveness
- `GET /readyz`  — readiness + dependency checks
- `GET /version` — service + version + start time
- `GET /metrics` — Prometheus text format
- `GET /docs`    — Swagger UI

## Environment

See `.env.example`. Critical vars for S2.5:

| Variable               | Default                            | Description |
|------------------------|------------------------------------|-------------|
| `PORT`                 | `4003`                             | Service port |
| `SBOM_PIPELINE_URL`    | `http://localhost:4007`            | Downstream SBOM pipeline |
| `VULN_INTEL_URL`       | `http://localhost:4008`            | Downstream vuln intel |
| `DEPENDENCY_INTEL_URL` | `http://localhost:4009`            | Downstream dep intel |
| `RATE_LIMIT_MAX`       | `10`                               | Per-route req/s cap |
| `RATE_LIMIT_WINDOW_MS` | `1000`                             | Per-route window |
| `METRICS_ENABLED`      | `true`                             | Master switch for prom-client metrics (S2.7) |
| `OTEL_SERVICE_NAME`   | `security-service`                 | Injected as the `service` label on every metric (per metrics-spec.md §5.1.1) |
| `METRICS_EXPOSE_ENDPOINT` | `true`                          | Expose `GET /metrics` for Prometheus scrape |
| `JWT_ALG`              | `HS256`                            | `RS256` in prod via `@aicc/auth` |
| `JWT_SECRET`           | dev-only                           | HS256 dev secret (Sprint 2 stub) |
| `JWT_PUBLIC_KEY`       | unset                              | RS256 public key (Sprint 2.1) |

## Events emitted (S2.5)

- `security.sbom.generated` — per successful `/sbom/generate`
- `security.vulnerability.detected` — per ingested vuln (severity → bus severity)
- `security.risk.calculated` — per top-5 riskiest component of a `/risk/calculate`

Topic constants live in `@aicc/shared/security`:
```ts
import { SBOM_TOPIC, VULN_TOPIC, RISK_TOPIC } from '@aicc/shared/security';
```

## Sprint 2.1 roadmap (not in this task)

- Replace HS256 stub with `jose`-based RS256 + JWKS via `@aicc/auth`
- Postgres-backed repositories (replace in-memory)
- Redis Streams event-bus (replace in-memory bus) — uses the same
  `EventBus` interface, so route handlers don't change
- Aggregation reads from a materialized view (`security.dashboard` table)
  refreshed by the security agent on a schedule
