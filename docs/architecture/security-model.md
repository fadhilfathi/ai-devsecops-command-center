# Security Model

> **Status**: Sprint 1 + Sprint 2 update (GitOpsManager). SecurityArchitect
> is the canonical owner of the threat-model section; GitOpsManager owns
> the **Service-to-service contracts** section and the **REST API surface**
> section (added in Sprint 2, O-3).
> **Owner**:
> - Threat model & RBAC: SecurityArchitect (canonical) → [`./authentication-and-security-design.md`](./authentication-and-security-design.md)
> - Event contracts & REST surface: GitOpsManager (Sprint 2)

## Purpose

This document describes the **security model** of the AI-DevSecOps Command
Center: who the actors are, how they authenticate, what they are
authorized to do, where the trust boundaries sit, and how we maintain
multi-tenant isolation.

It is **not** a substitute for [`SECURITY.md`](../../SECURITY.md) (vulnerability
disclosure) or for the compliance docs.

## Actors

| Actor           | Authenticates as            | Typical actions                          |
| --------------- | --------------------------- | ---------------------------------------- |
| **Operator**    | Human via SSO/OIDC          | Investigate, triage, approve             |
| **Admin**       | Human via SSO/OIDC          | Manage tenants, users, integrations      |
| **Service**     | Service identity (mTLS / token) | Internal API calls, consume bus      |
| **Agent**       | Service identity + scope    | Produce / consume bus, call tools        |
| **Webhook**     | HMAC of payload + secret    | Push external events (GitHub, etc.)      |
| **Auditor**     | Human via SSO (read-only)   | View audit log, export evidence          |

## Authentication

### User authentication (browser)

- **OIDC / SSO** is the primary flow (Auth0, Okta, Azure AD, Keycloak).
- A local username/password fallback is supported for break-glass but is
  logged loudly.
- Sessions are short-lived access tokens (15 min) plus rotating refresh
  tokens (30 days, sliding).
- MFA is **required** for all roles above `viewer`.

### Service-to-service

- **mTLS** within the cluster (cert-manager, SPIFFE-issued identities).
- The **API Gateway** terminates user auth; downstream services trust
  the gateway's `X-User-*` and `X-Tenant-*` headers **only** when mTLS
  is established.
- In dev, mTLS is optional; in staging and prod it is mandatory.

### Webhooks (inbound)

- Every webhook is verified by **HMAC-SHA256** of the raw body with a
  per-integration secret stored in the secret manager.
- Replay attacks are prevented with a 5-minute timestamp tolerance.

## Authorization (RBAC)

RBAC is **role-based** with **scope-based** granularity for actions and
**attribute-based** constraints (tenant, environment, asset tag).

### Built-in roles

| Role           | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| `super_admin`  | Platform operators (the people running the system)             |
| `tenant_admin` | Customer-side administrators                                   |
| `security_lead`| Triage, approve, configure scanners                            |
| `operator`     | Triage incidents, manage assets, run playbooks                 |
| `auditor`      | Read-only across the tenant, with export of audit logs         |
| `developer`    | View findings on their own projects, respond to PR comments     |
| `viewer`       | Read-only dashboard                                            |

### Scope examples

- `vulnerability:read`
- `vulnerability:write` (mark as resolved, suppress)
- `incident:read`
- `incident:respond`
- `incident:close`
- `compliance:evidence:read`
- `compliance:evidence:export`
- `integration:configure`

### Attribute constraints

- Every action is also gated by `tenant_id`; cross-tenant reads are
  impossible without an explicit, audited `tenant.admin` action.
- Some actions (e.g. opening an incident against a `production` asset)
  require an additional environment constraint; the user's roles must
  include the matching env tag.

## Multi-tenant isolation

- **Tenant** is a first-class column on every row of every business table.
- The data access layer injects a `WHERE tenant_id = $current_tenant` clause
  on every query; the only way around it is an explicit `withTenant(id)`
  call that the audit log records.
- **Database roles** per service, with permissions limited to its own
  schema. Cross-schema reads are forbidden by Postgres `GRANT`s.
- **Object-store prefixes** are tenant-scoped; bucket policies deny
  cross-prefix reads.
- **Cache keys** are prefixed with `tnt:<id>:`; the runtime refuses to
  set or read keys without the prefix.

## Threat model (STRIDE summary)

| Category      | Threats                                            | Primary mitigation |
| ------------- | -------------------------------------------------- | ------------------ |
| **S**poofing  | Stolen JWT, forged webhook                         | MFA, mTLS, HMAC    |
| **T**ampering | Mutating audit log, altering evidence              | Append-only audit, signed evidence |
| **R**epudiation| Operator denies action                            | Audit log with actor + trace |
| **I**nfo disc.| Cross-tenant leak via mis-scoped query             | Tenant filters in DAL, automated tests |
| **D**oS       | Runaway agent, event bus flood, expensive prompt   | Rate limits, circuit breakers, max-token budgets |
| **E**oP       | RBAC bypass, scope escalation                      | Centralized authz checks, fuzz tests |

A full threat model with diagrams is in [`/docs/security/threat-model.md`](../security/threat-model.md).

## Audit log

- **Every** state-changing action produces an audit record.
- Records are append-only, signed (HMAC chain), and replicated to an
  off-host store.
- Retention default: 365 days (configurable per tenant).
- Format: a subset of the event envelope + a hash of the previous record
  (hash-chained).

## Secret management

- **No secrets in `.env` files in production.** Use a real secret manager
  (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager).
- Secrets are read at startup; rotation is supported via a SIGHUP reload
  and a periodic refresh.
- All secret reads are themselves audit-logged.

## AI / agent safety

- Agents have a **declared blast radius**. An agent whose blast radius
  is "open incidents" cannot be promoted to a role that allows it to
  *close* incidents.
- The agent runtime enforces a **tool allowlist**. A prompt that tries to
  call an unauthorized tool is rejected and the run is failed loudly.
- All LLM inputs and outputs are **logged** (with secrets redacted) and
  retained for the audit period.
- The runtime enforces a **per-run token budget** and a **per-tenant
  daily token budget**.
- The runtime detects **prompt injection** patterns in tool outputs and
  refuses to follow instructions found in tool results.

## Service-to-service event contracts (Sprint 2)

The security stack — `sbom-pipeline` (4007), `vuln-intel` (4008),
`dependency-intel` (4009), and the `security-service` (3003) — exchanges
typed events on the event bus. The **canonical subject names and typed
event interfaces** live in
[`@aicc/shared/security`](../../backend/packages/shared/src/security/index.ts)
(a sub-path export of `@aicc/shared`, locked in ADR 0008).

> **Do not hardcode subject strings in service code.** Always import
> the constant from `@aicc/shared/security`. The string-form is in
> this document for clarity; the constant is the source of truth.

| Constant                | Subject                                       | Producer        | Consumers                                              | Schema path                                                          |
| ----------------------- | --------------------------------------------- | --------------- | ------------------------------------------------------ | -------------------------------------------------------------------- |
| `SBOM_TOPIC`            | `security.sbom.generated.v1`                  | sbom-pipeline   | dependency-intel, security-service, security-automation | `backend/models/security/sbom.model.ts`                              |
| `VULN_TOPIC`            | `security.vulnerability.detected.v1`          | vuln-intel      | dependency-intel, security-service, security-automation | `backend/models/security/vulnerability.model.ts`                     |
| `RISK_TOPIC`            | `security.risk.calculated.v1`                 | dependency-intel| security-service, security-automation                  | `backend/models/security/risk-score.model.ts`                        |

Versions follow the subject (`…v1`, `…v2`); a breaking payload change
requires a new subject version. See
[`./event-bus.md`](./event-bus.md#subject-naming) for the full
naming convention.

**Example consumer wiring** (Node.js / Fastify service):

```ts
import { SBOM_TOPIC, type SbomGeneratedEvent } from "@aicc/shared/security";

await bus.subscribe(
  { subject: SBOM_TOPIC, consumerGroup: "security-service" },
  async (msg) => {
    const event = msg.data as SbomGeneratedEvent;
    // event.sbom is CycloneDX-shaped (validated by Zod at the producer)
    // event.tenantId, event.gitSha, event.scanner are all present
  }
);
```

> **GitOps wire format:** the rich per-CVE `VulnerabilitySchema` is
> **projected** to a per-finding wire format (one event per
> `(CVE, affected)` pair) at the security-service :4003 boundary.
> The wire format is locked in
> [`security/wire-format/vulnerability-gitops-record.schema.json`](../../security/wire-format/vulnerability-gitops-record.schema.json)
> and documented in [`security/README.md`](../../security/README.md#vulnerability-ndjson-record-schema-gitops-wire-format-locked).
> The `.v1` subjects in the table above carry the rich schema; the
> wire format is a **superset payload**, not a different subject.

The full Zod schema (validator) and TypeScript type are exported **per
model** from `backend/models/security/`:

- `SbomSchema` / `Sbom` — CycloneDX 1.5-shaped (components, dependencies, metadata)
- `VulnerabilitySchema` / `Vulnerability` — normalised
  (CVSSv3, EPSS, KEV, aliases, severity)
- `DependencyGraphSchema` / `DependencyGraph` — nodes/edges with risk weights
- `RiskScoreSchema` / `RiskScore` — composite 0–100 + per-axis scores + dashboard types

## REST API surface (security-service, port 3003)

Five endpoints are added in Sprint 2 (S2.5) and are the public HTTP
surface of the security stack. All endpoints are OpenAPI-documented at
runtime via `@fastify/swagger` + `@fastify/swagger-ui` and rate-limited
at 10 req/s per route.

| Method | Path                          | Purpose                                    | RBAC                                | Idempotency key header | Status codes                            |
| ------ | ----------------------------- | ------------------------------------------ | ----------------------------------- | ---------------------- | --------------------------------------- |
| `POST` | `/sbom/generate`              | Kick off a SBOM generation job             | `security_engineer` / `platform_admin` | `Idempotency-Key` (UUIDv4)        | `202`, `400`, `401`, `403`, `409`, `429` |
| `POST` | `/sbom/analyze`               | Analyse an existing SBOM (no regen)        | `security_engineer` / `platform_admin` | `Idempotency-Key` (UUIDv4)        | `202`, `400`, `401`, `403`, `409`, `429` |
| `POST` | `/vulnerabilities/ingest`     | Bulk-ingest CVE feed (NVD/GHSA/OSV)        | `security_engineer` / `platform_admin` | `Idempotency-Key` (UUIDv4)        | `202`, `400`, `401`, `403`, `409`, `429` |
| `POST` | `/risk/calculate`             | Recompute risk for a tenant / scope        | `security_engineer` / `platform_admin` | `Idempotency-Key` (UUIDv4)        | `202`, `400`, `401`, `403`, `409`, `429` |
| `GET`  | `/security/dashboard`         | Aggregate view (scores, top vulns, trend)  | any authenticated role             | n/a                    | `200`, `401`, `429`                     |

**Auth:** HS256 or RS256 JWT (`Authorization: Bearer <jwt>`). The
HS256/RS256 selection is per-tenant (configured in tenant settings).
The middleware is `backend/services/security/src/middleware/auth.ts`.

**RBAC roles** (built-in, in `backend/services/security/src/middleware/rbac.ts`):

| Canonical role          | Aliases (in middleware)           | Can call POSTs         | Can call GETs |
| ----------------------- | --------------------------------- | ---------------------- | ------------- |
| `security_engineer`     | `sec_eng`, `security-engineer`    | ✅                     | ✅            |
| `platform_admin`        | `admin`, `platform-admin`         | ✅                     | ✅            |
| `tenant_admin`          | `tenant-admin`                    | ❌                     | ✅            |
| `security_lead`         | `sec_lead`, `security-lead`       | ❌ (read-only triage)  | ✅            |
| `operator`              | `ops`                             | ❌                     | ✅            |
| `auditor`               | `audit`                           | ❌                     | ✅            |
| `developer`             | `dev`                             | ❌                     | ✅            |
| `viewer`                | `view`                            | ❌                     | ✅            |

> **Tenant match:** All endpoints enforce `requireTenantMatch` — the
> JWT's `tenant_id` claim must match the request's `X-Tenant-Id` header
> (or the path's `:tenantId` param). Cross-tenant calls are 403'd and
> audit-logged.

**Idempotency:** POSTs accept an `Idempotency-Key` header (UUIDv4). The
service stores `{key, request_hash, response, expires_at}` for 24h.
Replays return the stored response (200) without re-running the work.

**Error envelope:** `application/problem+json` (RFC 7807) with `type`,
`title`, `status`, `detail`, `instance`, `traceId`, and a `code` (one
of `validation_failed`, `unauthorized`, `forbidden`, `not_found`,
`conflict`, `rate_limited`, `internal_error`). The
`backend/services/security/src/services/proxy.ts` file maps upstream
service errors to this envelope.

**Example — start a SBOM generation:**

```bash
curl -X POST https://api.example/security/sbom/generate \
  -H "Authorization: Bearer $JWT" \
  -H "X-Tenant-Id: tnt_01HXYZ" \
  -H "Idempotency-Key: 7e2a0e6a-1c8d-4f5e-8c79-3b9e6e1c8b2a" \
  -H "Content-Type: application/json" \
  -d '{
    "source": { "type": "git", "url": "https://github.com/fadhilfathi/ai-devsecops-command-center", "ref": "main" },
    "scope":  "monorepo",
    "formats": ["cyclonedx-json", "cyclonedx-xml", "spdx-json"]
  }'
# → 202 Accepted
# { "jobId": "job_01HXYZ", "status": "queued", "estimatedDurationSeconds": 120 }
```

## Future refactors (proposed; not blocking)

- **SRE-proposed split** of `.github/workflows/sbom.yml` ownership:
  SBOMPipelineAgent owns the workflow file content; GitOpsManager
  owns the runner/secret wiring in a shared `security-ci.yml`
  label-gated to a `security-ci` runner pool. Deferred to Sprint 3
  pending runner-pool rollout.
- **Egress proxy for AI providers** — currently the security service
  hits the upstream LLM providers directly. A dedicated egress proxy
  with per-tenant token budgets and request/response redaction would
  tighten the AI safety story; see ADR 0008 follow-up notes.
- **WebAuthn / passkey** for the Operator role — MFA via TOTP is the
  current default; passkeys are a 2026.H2 target.

## See also

- [`./authentication-and-security-design.md`](./authentication-and-security-design.md) — canonical auth, RBAC, sessions
- [`/docs/security/`](../security/) — operational security
- [`/docs/compliance/`](../compliance/) — control mapping
- [`SECURITY.md`](../../SECURITY.md) — disclosure policy
- [`/docs/adr/`](../adr/) — architecture decision records
