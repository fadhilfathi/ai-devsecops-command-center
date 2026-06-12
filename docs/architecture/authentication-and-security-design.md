# Authentication & Security Design

> **Document Owner:** SecurityArchitect
> **Sprint:** 1 (Foundation)
> **Status:** Approved for implementation
> **Classification:** Internal — Engineering
> **Last Updated:** 2026-06-12
> **Related Docs:**
> - [security-model.md](./security-model.md) — architecture-level overview (PlatformArchitect)
> - [system-architecture.md](./system-architecture.md)
> - [event-bus.md](./event-bus.md)
> - [github-integration.md](./github-integration.md)

---

## 1. Purpose & Scope

This document is the **detailed Authentication & Security Design** for the AI-DevSecOps Command Center. It is the engineering reference that implements the architecture-level overview in [`security-model.md`](./security-model.md) and provides the concrete specifications, algorithms, and configurations that backend services must follow.

**This document is authoritative** for:
- Token formats, lifetimes, and rotation policies
- RBAC permission catalog and resolution algorithm
- Session management tables and policies
- Multi-tenant isolation strategy
- Secret management approach
- Cryptographic algorithm selection
- Audit log format and integrity
- API security headers, CORS, CSRF, and rate limiting
- Service-to-service trust model

The shorter [security-model.md](./security-model.md) is the **onboarding-friendly summary**; this document is the **deep spec**.

---

## 2. Design Principles

| # | Principle | Implication |
|---|-----------|-------------|
| 1 | **Zero Trust by default** | Every request is authenticated and authorized; no implicit trust between services or networks. |
| 2 | **Least privilege** | Roles, service accounts, and tokens are scoped to the minimum permissions required. |
| 3 | **Defense in depth** | Layered controls (network → identity → application → data) so a single failure does not breach the system. |
| 4 | **Fail closed** | If an auth/audit check is unreachable, the request is **denied** and a security event is raised. |
| 5 | **Tenant isolation is non-negotiable** | Tenant boundaries are enforced at the data layer, not just the UI. |
| 6 | **Verifiable, not presumed** | Every security decision produces an audit record. |
| 7 | **Secure by default configuration** | New services ship with secure defaults; insecure config requires explicit opt-in. |
| 8 | **Cryptographic agility** | Algorithms are abstracted so they can be rotated without code changes. |

---

## 3. Identity Model

### 3.1 Identity Types

| Identity | Description | Authentication | Lifetime |
|----------|-------------|----------------|----------|
| **Human User** | Engineer, security analyst, compliance officer, admin | Username + password + TOTP MFA, or SSO (OIDC/SAML) | Long-lived, human-managed |
| **Service Account** | Backend service authenticating to other services | mTLS or signed JWT (client credentials grant) | Long-lived, machine-managed |
| **AI Agent Identity** | Autonomous agents (Scanner, Triage, Remediation) | Short-lived JWT issued by Agent Service; scoped to specific capabilities | Short-lived (≤15 min) |
| **Integration Identity** | GitHub App, Slack, Jira, etc. | OAuth2 or App-signed JWT (per provider) | Provider-managed, rotated |
| **API Key Holder** | Programmatic external access (read-only) | Static API key + HMAC signature | Long-lived, revocable |

### 3.2 Identity Storage

- **Primary store:** PostgreSQL table `identities` (in the Auth service database).
- **Password hashing:** Argon2id with parameters `m=64MB, t=3, p=1` (OWASP 2025 baseline).
- **Sensitive PII (email, phone):** Encrypted at rest with AES-256-GCM via a per-tenant data key (envelope encryption).
- **Soft delete only:** Identities are never hard-deleted; they are flagged `disabled_at` to preserve audit history.

### 3.3 Authentication Flows

#### 3.3.1 Human Login (Password)

```
┌────────┐          ┌────────┐         ┌────────┐
│ Browser│  ① POST  │  Auth  │  ② lookup│  PG    │
│        │  /login  │  Svc   │────────►│  users │
│        │─────────►│        │         │        │
│        │  ③ verify│        │  ④ log  │        │
│        │◄─────────│        │────────►│ audit  │
│        │  access  │        │  ⑤ issue│        │
│        │  + ref   │        │  jwt    │        │
│        │  token   │        │         │        │
└────────┘          └────────┘         └────────┘
```

- Rate limit: 5 failed attempts per 15 min per (IP, username) tuple.
- After 10 failed attempts in 24h: account is locked; admin unlock required.
- Successful login rotates the **refresh token family** (see §6).

#### 3.3.2 SSO (OIDC)

- Supports any OIDC-compliant IdP (Okta, Azure AD, Google Workspace, Auth0).
- Scopes requested: `openid profile email groups`.
- **Just-in-time provisioning** on first SSO login creates the identity with no password set.
- Group claim → RBAC role mapping is configured per-tenant (admin-managed).
- JIT users are flagged `is_managed_by_sso=true`; local password is disabled.

#### 3.3.3 MFA

- **Required for:** all human users in `Admin` or `Owner` roles.
- **Recommended for:** all human users.
- **Supported factors:** TOTP (RFC 6238), WebAuthn (passkey / hardware key), push (optional, provider-dependent).
- **Backup codes:** 10 single-use recovery codes generated at MFA enrollment.

#### 3.3.4 Service-to-Service (mTLS or JWT)

- **Default:** Short-lived JWT issued by the Auth service using the OAuth2 client-credentials grant.
- **For high-trust internal links:** mTLS with SPIFFE-issued workload identities.
- Service tokens are bound to:
  - `service_id` (issuer)
  - `aud` (target service)
  - `scopes` (granted permissions)
  - `tenant_id` (scoped tenant, or `*` for platform-internal services)

---

## 4. Token Architecture

### 4.1 Access Token (JWT)

| Property | Value |
|----------|-------|
| Algorithm | **RS256** (asymmetric) — allows public-key verification by services |
| Key rotation | Every 90 days; JWKS endpoint advertises current + next key |
| Lifetime | **15 minutes** (human) / **5 minutes** (agent) |
| Claims | `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `tenant_id`, `roles`, `scopes`, `sid` |
| Storage (client) | **Memory only** (never `localStorage`) |
| Transport | `Authorization: Bearer <jwt>` header — required over HTTPS |

**Critical claim meanings:**
- `tenant_id` — required; rejected if missing or malformed
- `roles` — array of role names resolved from RBAC
- `scopes` — fine-grained permission strings
- `sid` — session id; enables server-side revocation
- `jti` — unique token id; logged for forensics

### 4.2 Refresh Token (Opaque)

- 256-bit cryptographically random string, stored as **SHA-256 hash** in the Auth DB.
- Lifetime: **14 days** for human users, **24 hours** for service accounts.
- **Sliding window:** each use issues a new refresh token; old one is invalidated.
- **Family revocation:** if a previously-rotated refresh token is presented, the entire family is revoked (replay detection).
- Stored in an **HttpOnly, Secure, SameSite=Strict** cookie by the frontend; never exposed to JavaScript.

### 4.3 Token Revocation

- **Server-side:** a `revoked_sessions` table tracks revoked `jti` and `sid` values.
- **Cache:** revoked token ids are pushed to a Redis set with `TTL = token remaining lifetime`.
- **Check order:** services fetch JWKS → verify signature → check `revoked` set in Redis → check claims.
- **Bulk revocation:** "log out everywhere" or "compromised account" revokes the entire session family.

### 4.4 JWKS Endpoint

- `GET /.well-known/jwks.json` — public key set for token verification.
- Cached by services for ≤5 minutes.
- Key rotation: new key is published **before** the old one is retired; both are valid during the overlap window.

---

## 5. Authorization (RBAC)

### 5.1 Model

- **Role-Based Access Control** with optional **ABAC overlays** (attribute-based) for tenant-scoped resources.
- Permissions are expressed as `action:resource` strings, e.g. `read:incidents`, `write:policy`, `delete:asset`.
- Roles are **collections of permissions**, never hard-coded in services.
- Roles are **per-tenant**; the same user can hold different roles in different tenants.

### 5.2 System Roles

| Role | Purpose | Key Permissions |
|------|---------|-----------------|
| `owner` | Tenant owner, billing | `*` (all permissions within their tenant) |
| `admin` | Tenant administration | All except billing and ownership transfer |
| `security_admin` | Manage security configuration, policies, integrations | `*` on `policy`, `integration`, `vulnerability`, `incident` |
| `security_analyst` | Triage vulnerabilities and incidents | `read:*`, `write:incident`, `write:vulnerability` (status/comment only) |
| `developer` | View findings on their repos, acknowledge | `read:asset`, `read:vulnerability`, `read:sbom`, `ack:vulnerability` |
| `compliance_officer` | Read-only audit, evidence collection | `read:compliance`, `read:audit_log`, `export:report` |
| `viewer` | Read-only across tenant | `read:*` |
| `agent` | Reserved for AI agents (system-issued) | Scoped per agent (see §5.4) |
| `service` | Reserved for service accounts | Scoped per service |

### 5.3 Permission Resolution Algorithm

```
is_allowed(user, action, resource):
  1. token must be valid (sig + exp + not revoked)
  2. token.tenant_id must match resource.tenant_id
  3. roles = lookup(token.roles, tenant_id)
  4. for role in roles:
       if role.permissions contains "action:resource":
            return ALLOW
       if role.permissions contains "action:*" or "*:resource":
            return ALLOW
  5. if resource.owner_id == token.sub: return ALLOW for "read" or "update"
  6. return DENY
```

This algorithm is implemented as a **shared authorization library** (`@command-center/authz`) imported by every service. It is the **only** path for permission decisions.

### 5.4 Agent Authorization

AI agents receive **capability tokens** rather than roles:

```json
{
  "sub": "agent:scanner-7f3a",
  "scopes": [
    "scan:asset:read",
    "scan:asset:execute",
    "scan:result:write"
  ],
  "tenant_id": "tenant-acme",
  "exp": 1735689600
}
```

- Capabilities are issued by the Agent Service **per task**, not per session.
- A scanner task gets `scan:*`; a remediation agent gets `remediate:vulnerability:suggest` only (it cannot apply without human approval).
- Capabilities are **revocable individually** without affecting other tasks.

### 5.5 ABAC Overlays

For sensitive actions, additional attributes are checked:

| Action | ABAC Conditions |
|--------|-----------------|
| `delete:asset` | Tenant must not be in `read_only` mode (e.g., during legal hold) |
| `export:sbom` | User must have MFA verified in last 24h; export is logged with reason |
| `apply:remediation` | Requires second-person approval for high/critical CVEs |
| `manage:tenant` | Caller IP must be in tenant-allowed IP allowlist (optional, tenant-configurable) |

---

## 6. Session Management

### 6.1 Session Lifecycle

```
   ┌──────────┐    login     ┌─────────────┐
   │ Anonymous│─────────────►│ Authenticated│
   └──────────┘              └──────┬──────┘
                                    │ activity
                                    ▼
                            ┌──────────────┐
                            │   Active     │◄─────┐
                            │  Session     │      │ refresh
                            └──┬─────┬─────┘      │
                  idle timeout│     │logout       │
                               ▼     ▼             │
                       ┌──────────┐ ┌────────┐     │
                       │ Expired  │ │Logged  │─────┘
                       └──────────┘ │ Out    │ re-login
                                    └────────┘
```

### 6.2 Session Table

| Field | Type | Purpose |
|-------|------|---------|
| `sid` | UUID v7 (PK) | Session id; embedded in JWT |
| `identity_id` | UUID FK | Owner of the session |
| `tenant_id` | UUID | Active tenant (multi-tenant users) |
| `ip` | INET | Originating IP (for binding) |
| `user_agent_hash` | BYTEA | SHA-256 of UA (for binding) |
| `created_at` | TIMESTAMPTZ | Session start |
| `last_active_at` | TIMESTAMPTZ | For idle timeout |
| `expires_at` | TIMESTAMPTZ | Hard expiry |
| `revoked_at` | TIMESTAMPTZ NULL | Revocation marker |
| `mfa_verified_at` | TIMESTAMPTZ NULL | Required for sensitive actions |

### 6.3 Session Policies

| Setting | Value | Override |
|---------|-------|----------|
| Idle timeout | 30 minutes | Tenant-configurable (5 min – 8 h) |
| Absolute lifetime | 14 days | Fixed |
| Concurrent sessions | 10 per user | Tenant-configurable (1 – 100) |
| Step-up MFA re-prompt | Every 12 hours | Tenant-configurable |
| New device login | Re-prompt MFA + email notify | Required |

### 6.4 Concurrent Session Handling

- New login beyond limit: **oldest non-revoked session is revoked** and the user is notified.
- Admins can view and revoke sessions for users in their tenant via the UI.

---

## 7. Multi-Tenant Isolation

### 7.1 Tenant Hierarchy

```
Platform
  └── Tenant (organization)
        ├── Project / Repository Group
        │     └── Asset (repository, image, deployment)
        └── Integration
```

- A **Tenant** is the security and billing boundary.
- Users are members of one or more Tenants.
- Service accounts belong to a single Tenant.
- Agents are scoped to a single Tenant for the duration of a task.

### 7.2 Data Isolation Strategy: **Tenant ID on every row + Postgres RLS**

- Every business table has a `tenant_id` column (NOT NULL).
- **Row-Level Security (RLS)** is enabled on every business table.
- A `current_setting('app.tenant_id')` GUC is set per request; RLS policies compare it to `tenant_id`.
- **Bypass:** only the platform-internal "control plane" role (used for billing, audit) bypasses RLS, and it cannot read business data — it only manages tenants.
- **Schema-level isolation** is used for **regulated tenants** (e.g., FedRAMP) as an opt-in upgrade.

### 7.3 Tenant Context Propagation

```
HTTP request
    │
    ▼
API Gateway extracts JWT, sets X-Tenant-Id header (verified against token)
    │
    ▼
Service receives request
    │
    ▼
DB middleware runs: SELECT set_config('app.tenant_id', $1, true)
    │
    ▼
All subsequent queries are RLS-scoped
```

The middleware **must** run before any business query. A request without a verified `tenant_id` is rejected with `401`.

### 7.4 Cross-Tenant Operations

- Cross-tenant queries are **forbidden** in normal flow.
- Exception path: a `platform_admin` (a security-controlled role, separate from tenant admins) can be granted cross-tenant visibility for support cases; this is **logged, time-bound, and reason-coded**.

### 7.5 Tenant Onboarding

1. Tenant record created in control plane DB.
2. First `owner` user invited; sets password + MFA.
3. Tenant is in **isolated mode by default** — no integrations active, no agents running.
4. Owner enables integrations and agent capabilities.

---

## 8. API Security

### 8.1 Transport

- TLS 1.3 only (TLS 1.2 disabled except for legacy webhook receivers).
- HSTS with `max-age=63072000; includeSubDomains; preload`.
- Certificate automation via cert-manager / Let's Encrypt.

### 8.2 Input Validation

- All inputs validated against a JSON Schema at the service boundary.
- Maximum request body size: 10 MB (default; per-endpoint override).
- File uploads (SBOM, evidence) limited to 50 MB; type-checked by magic number, not extension.
- SQL: parameterized queries only; **no string concatenation into SQL**.
- NoSQL: schema-validated at the application layer.

### 8.3 Output Encoding

- JSON responses use a strict serializer that escapes `<`, `>`, `&`, `"`, `'`.
- Frontend uses a framework that escapes by default (React); `dangerouslySetInnerHTML` is forbidden by lint rule.

### 8.4 CORS

- Allowed origins: **explicit per-tenant list**, stored in config.
- Default: same-origin only.
- Credentials: `true` only when origin is in allowlist.
- Preflight is cached for ≤5 min.

### 8.5 CSRF

- All state-changing requests require a CSRF token:
  - Web (cookie-auth): token in `X-CSRF-Token` header, double-submit cookie pattern.
  - Bearer-auth APIs: CSRF not applicable (bearer in header, not auto-sent).
- Tokens are bound to the session and rotated on login.

### 8.6 Rate Limiting

- **Per-IP:** 1000 req/min (gateway-level).
- **Per-identity:** 600 req/min (auth-level).
- **Per-endpoint overrides** (e.g., `/auth/login`: 10 req/min per IP).
- **Backed by Redis** token-bucket; 429 with `Retry-After`.

### 8.7 Request Signing (Webhooks)

- Inbound webhooks (GitHub, GitLab, etc.) are signature-verified.
  - GitHub: `X-Hub-Signature-256` HMAC SHA-256 of the raw body.
- Outbound webhooks from the Command Center are signed with an **HMAC per-receiver secret**; receivers verify before acting.

### 8.8 Security Headers

All HTTP responses include:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

CSP is per-frontend; report-only in dev, enforce in prod.

---

## 9. Secret Management

### 9.1 Where Secrets Live

| Environment | Store | Examples |
|-------------|-------|----------|
| Local dev | `.env.local` (git-ignored) + OS keychain fallback | DB passwords, API keys |
| CI / build | Vault Agent sidecar injects env vars | Sign keys, container registry creds |
| Production | **HashiCorp Vault** (or cloud KMS-backed secret store) | DB creds, JWT signing keys, webhook secrets, third-party API keys |
| Container runtime | Env vars populated by Vault Agent; never baked into image | Same as prod |

### 9.2 Secret Rotation

- **JWT signing keys:** 90 days, automated via Vault PKI.
- **Database passwords:** 30 days for service accounts, 90 days for humans.
- **Third-party API keys:** on demand, plus automatic quarterly rotation for non-prod.
- **Webhook secrets:** 180 days, rotation does not break in-flight deliveries (dual-secret window).

### 9.3 No Secrets in Code or Logs

- Pre-commit hook (gitleaks) blocks commits containing known secret patterns.
- Log scrubber strips patterns matching API key, JWT, password, and credit card regexes.
- Error responses to clients never include internal stack traces or secrets.

---

## 10. Cryptography

### 10.1 Algorithms

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Password hashing | Argon2id (m=64MB, t=3, p=1) | OWASP 2025 |
| Token signing | RS256 (2048-bit RSA) | Rotated quarterly |
| Token encryption (refresh) | AES-256-GCM | Envelope with per-tenant KEK |
| Data at rest (DB) | AES-256-GCM | Cloud-provider managed keys (KMS), per-tenant DEK |
| Data at rest (object storage) | AES-256 | Server-side encryption, SSE-KMS |
| TLS | TLS 1.3 | AEAD suites only (AES-GCM, ChaCha20-Poly1305) |
| Hashing (file integrity) | SHA-256 | For SBOM and artifact integrity |
| HMAC (webhook signing) | HMAC-SHA-256 | With constant-time compare |
| Random | `crypto.randomBytes` / `crypto.randomUUID` | Cryptographically secure |

### 10.2 Key Management

- All keys stored in **Vault** or **cloud KMS**; never on disk in plain form.
- **KMS** is the root of trust; **Vault** is the broker.
- Key access is logged to the audit trail.
- **HSM-backed keys** for production JWT signing (FIPS 140-2 Level 2+).

### 10.3 Algorithm Agility

- All crypto operations go through a `CryptoProvider` interface, allowing algorithm swap without touching call sites.
- A deprecation log warns when an outdated algorithm is used.

---

## 11. Threat Model (STRIDE)

### 11.1 Threats Considered

| Category | Threat | Mitigation |
|----------|--------|------------|
| **Spoofing** | Stolen JWT used from attacker IP | Short token lifetime, IP binding (optional), anomaly detection |
| **Spoofing** | Forged GitHub webhook | HMAC signature verification with constant-time compare |
| **Tampering** | SQL injection | Parameterized queries, RLS, input validation |
| **Tampering** | SBOM tampering in transit | SHA-256 hash + signature, signed URLs only |
| **Repudiation** | User denies performing an action | Append-only audit log with cryptographic chaining |
| **Information Disclosure** | Cross-tenant data leak | RLS on every table, tenant_id in JWT, integration tests |
| **Information Disclosure** | Secret in log | Log scrubber, pre-commit secret scanning |
| **Denial of Service** | Auth endpoint flooding | Rate limit, CAPTCHA on login after threshold |
| **Denial of Service** | Large SBOM upload | Size limit, streaming parser, async processing |
| **Elevation of Privilege** | RBAC bypass attempt | Centralized authz library, deny-by-default, fuzz tests |
| **Elevation of Privilege** | Agent acting outside capability | Short-lived, narrowly-scoped capability tokens, post-hoc audit |

### 11.2 Out-of-Scope Threats (handled by other layers)

- Physical security of cloud provider data centers.
- DDoS at the network edge (mitigated by WAF/CDN).
- Supply chain attacks on dependencies (handled in CI by SRE + Compliance).

### 11.3 Trust Boundaries

```
[ Untrusted Internet ]
        │ TLS
        ▼
[ WAF / API Gateway ] ←── rate limit, signature verify
        │
        ▼
[ Service Mesh / mTLS ] ←── internal trust
        │
        ▼
[ Auth Service ] ←── token verification
        │
        ▼
[ Business Service ] ←── authz check
        │
        ▼
[ Database (RLS) ] ←── tenant scoping
```

Every arrow is a trust boundary; every boundary is a control point.

---

## 12. Audit Logging

### 12.1 What is Logged

| Event Class | Examples |
|-------------|----------|
| **Auth events** | login success/fail, logout, MFA enroll, password change, SSO link |
| **Authz decisions** | denied actions (always), allowed sensitive actions |
| **Identity changes** | user created, role granted/revoked, MFA disabled |
| **Tenant events** | tenant created, member added, settings changed |
| **Data access** | SBOM exported, evidence downloaded, audit log viewed |
| **Integration events** | GitHub App installed, webhook received, scanner task launched |
| **Agent events** | agent task issued, capability granted, anomaly flagged |
| **Admin events** | policy changed, integration enabled/disabled, secret rotated |

### 12.2 Audit Record Schema

```json
{
  "id": "01J...ULID",
  "ts": "2026-06-12T14:23:11.482Z",
  "tenant_id": "uuid",
  "actor": {
    "type": "user|service|agent|integration",
    "id": "uuid",
    "ip": "203.0.113.42",
    "user_agent": "..."
  },
  "action": "vulnerability.acknowledge",
  "target": { "type": "vulnerability", "id": "CVE-..." },
  "decision": "allow|deny",
  "reason": "permission:ack:vulnerability",
  "request_id": "uuid",
  "trace_id": "w3c-traceparent",
  "prev_hash": "sha256...",
  "hash": "sha256...",
  "metadata": { ... }
}
```

### 12.3 Integrity

- Each record contains `hash = SHA256(prev_hash || canonical(record))`.
- The chain is **append-only**; a daily anchor is published to object storage with object lock (WORM).
- Tamper detection: nightly job verifies the chain; alerts on mismatch.

### 12.4 Retention

- **Hot (queryable):** 90 days in PostgreSQL.
- **Warm (searchable):** 1 year in object storage (Parquet).
- **Cold (archival):** 7 years (compliance-driven; HIPAA, SOC 2, GDPR).
- **Tamper-evident export** (signed bundle) available to compliance officers.

---

## 13. Security Monitoring & Detection

### 13.1 Detection Signals

- **Brute force:** ≥10 failed logins on one account in 5 min → alert + temp lock.
- **Impossible travel:** login from geographically distant IPs in <1h → force re-auth + notify.
- **Bulk export:** >1000 records exported in 5 min → alert security_admin.
- **Privilege escalation:** role grant to non-admin by non-admin → require approval.
- **Anomalous agent behavior:** agent task exceeds expected scope or duration → kill switch.
- **Webhook signature failure:** ≥3 in 10 min → quarantine source IP for 1h.
- **Token replay:** refresh token used twice → revoke session family + alert.

### 13.2 Response Automation

- High-confidence detections (e.g., impossible travel + new device) trigger **automatic session revocation**.
- Medium-confidence detections create a security **incident** in the Incident service for triage.
- All actions taken by automation are themselves audit-logged.

---

## 14. Service-to-Service Security

### 14.1 East-West Traffic

- All service-to-service calls go through the **service mesh** (Linkerd or Istio).
- **mTLS** by default; service identity from SPIFFE.
- Authorization policies on the mesh: service A can only call service B's `/v1/allowed-paths`.
- Service tokens (JWT) are still required for application-level authz.

### 14.2 Service Identity

- Each service has a **SPIFFE ID** of the form `spiffe://command-center/ns/<ns>/sa/<service-name>`.
- Workload certificates auto-rotated by the mesh.
- No shared service accounts across services.

### 14.3 Database Access

- Services connect to the DB with **per-service credentials**.
- Credentials are Vault-issued and short-lived (≤24h).
- Direct DB access from outside the cluster is **forbidden**; only bastion + break-glass is allowed (fully audited).

---

## 15. Frontend Security

| Control | Implementation |
|---------|----------------|
| XSS | React escaping by default; no `dangerouslySetInnerHTML`; CSP enforced |
| Token storage | Access token in memory; refresh token in HttpOnly cookie |
| Clickjacking | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| Open redirect | Login redirect URIs are validated against a per-tenant allowlist |
| Dependency security | `npm audit` on every PR; Renovate keeps deps current; SBOM published per release |
| Subresource integrity | Static assets loaded with SRI hashes |
| Form validation | Client-side validation mirrors server JSON Schema |

---

## 16. CI/CD & Deployment Security

| Stage | Control |
|-------|---------|
| Source | Branch protection, required reviews, signed commits (recommended) |
| Build | Reproducible builds, SBOM generated, image signed (cosign) |
| Scan | SAST, dependency scan, secret scan, IaC scan in pipeline |
| Stage | Auto-deploy to staging; smoke + security regression tests |
| Prod | Manual approval for prod; blue/green or canary deploy; auto-rollback on SLO breach |
| Runtime | Admission controller enforces: no `:latest`, no privileged containers, resource limits set, read-only root FS preferred |
| Post-deploy | Continuous vulnerability scan of running images; auto-PR for patches |

---

## 17. Privacy & Data Protection

### 17.1 Data Classification

| Class | Examples | Controls |
|-------|----------|----------|
| **Public** | Marketing docs, public SBOMs | None special |
| **Internal** | Most operational data | Auth required, tenant scoped |
| **Confidential** | Vulnerability details, PII | Encrypted at rest, access logged |
| **Restricted** | Auth secrets, signing keys, customer PII at scale | HSM/KMS, dual-control access |

### 17.2 PII Handling

- **Minimize:** collect only what is needed.
- **Encrypt:** at rest (per §10) and in transit.
- **Redact:** in logs, error messages, and non-prod environments.
- **Erasure:** GDPR right-to-erasure is supported; soft delete of PII, hard delete of credentials; anonymize audit logs of the erased subject.

### 17.3 Data Residency

- Default: tenant data in the region chosen at tenant creation.
- **EU tenants:** data stays in EU region; no cross-region replication of business data.
- A tenant may opt into multi-region for DR with documented controls.

---

## 18. Break Glass & Emergency Access

- **Break-glass account** is a platform-level emergency identity held in escrow (Vault + paper backup).
- Use requires dual approval from two named security officers and a written justification.
- Every break-glass action is alerted in real time to the security team.
- All break-glass sessions are recorded (terminal + UI) and reviewed within 24h.

---

## 19. Compliance Touchpoints

This design satisfies:

- **SOC 2 Type II** — control mapping by ComplianceOfficer.
- **ISO 27001 / 27017 / 27018** — A.9 (access), A.10 (crypto), A.12 (ops security), A.13 (comms security).
- **GDPR** — data minimization, encryption, right to erasure.
- **NIST 800-53 rev. 5** — AC, AU, IA, SC families.
- **CIS Controls v8** — mapping maintained by ComplianceOfficer.

See `compliance-mapping.md` (delivered by ComplianceOfficer) for the control-by-control crosswalk.

---

## 20. Service Implementation Checklist

Each backend service **must** implement, in order:

- [ ] JWT verification middleware (uses `@command-center/authn`)
- [ ] Tenant context middleware (sets `app.tenant_id`)
- [ ] Authorization library (`@command-center/authz`) — no custom checks
- [ ] Request validation (JSON Schema)
- [ ] Structured logging with `request_id` and `trace_id`
- [ ] Audit log emission for all sensitive actions
- [ ] Rate limit (inherits from gateway; per-endpoint override)
- [ ] Health and readiness endpoints
- [ ] mTLS configured at mesh level
- [ ] Secret resolution from Vault at startup
- [ ] Output serializer with strict escaping
- [ ] Error handler that does not leak internals
- [ ] OpenAPI spec published for the service

---

## 21. Open Questions / Future Work

| Topic | Owner | Status |
|-------|-------|--------|
| FIPS 140-3 enforcement for regulated tenants | SecurityArchitect + SRE | To scope |
| SCIM provisioning for enterprise IdPs | PlatformArchitect | Backlog |
| Customer-managed encryption keys (BYOK) | SecurityArchitect | Design in Q3 |
| Continuous access evaluation (CAE) for OAuth2 | SecurityArchitect | Research |
| Risk-based authentication (device fingerprint, behavior) | SecurityArchitect | Roadmap |
| Tenant-configurable session policies (already supported; needs UI) | UIUXEngineer | Backlog |

---

## 22. References

- OWASP ASVS v4.0.3 — Application Security Verification Standard
- OWASP API Security Top 10 (2023)
- NIST SP 800-53 Rev. 5 — Security and Privacy Controls
- NIST SP 800-63B — Digital Identity Guidelines (Authenticator Assurance Levels)
- CIS Controls v8
- IETF RFC 8725 — JSON Web Token Best Current Practices
- IETF RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- SPIFFE / SPIRE — Workload Identity
- HashiCorp Vault documentation

---

*End of Authentication & Security Design.*
