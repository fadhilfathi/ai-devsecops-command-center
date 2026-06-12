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
