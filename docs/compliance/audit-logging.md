---
title: Audit Logging Requirements
owner: ComplianceOfficer
status: draft
version: 0.1.0
last_updated: 2026-06-12
related:
  - ./nist-800-53.md#au--audit-and-accountability
  - ./cis-controls-v8.md#control-08--audit-log-management
  - ../architecture/monitoring-architecture.md
  - ../architecture/security-model.md
---

# Audit Logging Requirements

This document defines the requirements for the AI-DevSecOps Command
Center's audit log subsystem. It is the source of truth for:

- **What must be logged** — the event catalog.
- **What each record must contain** — the record schema.
- **How records are protected** — integrity, confidentiality, retention.
- **Who can access them** — access control and break-glass.
- **How they are reviewed** — automated and human review cadence.
- **How they are produced and shipped** — pipeline architecture.

> Mapping: AU (NIST 800-53) in [`nist-800-53.md`](./nist-800-53.md#au--audit-and-accountability);
> CIS 8 (Audit Log Management) in [`cis-controls-v8.md`](./cis-controls-v8.md#control-08--audit-log-management).

## 1. Goals

The audit log subsystem exists to:

1. **Detect** security-relevant events across all platform components.
2. **Reconstruct** the timeline of an incident, including the actions of
   any user (human or service) that touched customer data or platform
   configuration.
3. **Evidence** control operation to internal and external auditors
   (SOC 2, ISO 27001, customer attestations).
4. **Support** customer compliance — the platform also produces
   customer-scoped audit data for the customer's own auditors.
5. **Defend** the integrity of the log itself, so that an attacker who
   compromises a component cannot rewrite history.

## 2. Scope

In scope:

- All platform services (Auth, Agent, Security, Incident, Compliance,
  Integration, Event Bus, Edge, Frontend BFF, background workers).
- The control plane (CI/CD, IaC, secrets, KMS, observability stack).
- The data plane (per-tenant data stores, caches, message streams).
- Customer-facing surfaces (UI, API, webhooks, integrations).

Out of scope (covered elsewhere):

- Cloud-provider audit logs (CloudTrail / Azure Activity) — these are
  *ingested* but the authoritative retention and review is the cloud
  provider's responsibility; see inherited controls in
  [`nist-800-53.md`](./nist-800-53.md).
- Network flow logs (VPC / VNet flow logs) — collected by the SRE team,
  retained in their own storage tier; cross-referenced for incident
  investigation.

## 3. Event catalog

The following event types **must** be logged. Each row specifies the
**actor** (who), **action** (what), **object** (target), and the
required **disposition** (outcome). The full event type registry is
maintained in `backend/services/audit/src/events.ts`.

### 3.1 Identity & authentication

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `auth.login.success` | user / service | session | tenant_id, user_id, mfa_used, source_ip, user_agent |
| `auth.login.failure` | user / service | session | reason, attempted_username_hash, source_ip |
| `auth.logout` | user | session | session_id |
| `auth.mfa.challenge` | user | session | method, success |
| `auth.mfa.enroll` | user | user | method |
| `auth.password.changed` | user | user | — |
| `auth.token.issued` | service | token | scope, ttl, audience |
| `auth.token.revoked` | service / user | token | reason |
| `auth.session.locked` | system | user | reason |
| `auth.account.locked` | system | user | reason (e.g., 5 failed attempts) |
| `auth.account.disabled` | admin | user | reason |
| `auth.account.deleted` | admin | user | reason |
| `auth.impersonation.started` | admin | user | justification (required) |
| `auth.impersonation.ended` | admin | user | duration |

### 3.2 Authorization & access

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `authz.access.granted` | user / service | resource | resource_type, resource_id, action, policy_id |
| `authz.access.denied` | user / service | resource | reason (policy_id, missing scope, etc.) |
| `authz.role.granted` | admin | user | role, granted_scope |
| `authz.role.revoked` | admin | user | role, revoked_scope |
| `authz.policy.created` | admin | policy | policy_hash |
| `authz.policy.updated` | admin | policy | diff_hash |
| `authz.policy.deleted` | admin | policy | reason |

### 3.3 Data access (per-tenant)

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `data.read` | user / service | record | tenant_id, record_type, record_id, classification |
| `data.write` | user / service | record | same; plus before/after hash |
| `data.delete` | user / service | record | same |
| `data.export` | user / service | dataset | dataset_id, format, row_count, hash |
| `data.share.created` | user | share_link | scope, ttl, watermark |
| `data.share.revoked` | user | share_link | — |
| `data.access.anomaly` | system | user | anomaly_type, score |

### 3.4 Configuration change

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `config.updated` | user / service | setting | tenant_id, setting_path, old_hash, new_hash, pr_url |
| `config.deleted` | user / service | setting | same |
| `config.bulk.imported` | user | scope | import_id, item_count, source |
| `config.policy.changed` | user | policy | diff_summary |

### 3.5 Vulnerability & incident lifecycle

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `vuln.found` | scanner | finding | cve, severity, cvss, epss, asset_id |
| `vuln.triaged` | user | finding | priority, assignee |
| `vuln.suppressed` | user | finding | reason, expiry |
| `vuln.remediated` | user / automation | finding | pr_url, fix_version |
| `vuln.reopened` | system | finding | reason |
| `incident.created` | user / system | incident | severity, category, source |
| `incident.escalated` | system | incident | new_severity, reason |
| `incident.closed` | user | incident | resolution_code |
| `incident.postmortem.published` | user | incident | url |

### 3.6 Agent & integration

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `agent.enrolled` | agent | host | host_id, tenant_id, agent_version |
| `agent.unenrolled` | user / system | host | reason |
| `agent.heartbeat.missed` | system | host | duration, last_seen |
| `agent.finding.uploaded` | agent | finding | finding_type, target_id |
| `integration.connected` | user | integration | provider, scopes |
| `integration.disconnected` | user | integration | reason |
| `integration.token.rotated` | system | integration | — |
| `integration.api_call` | integration | resource | provider, action, result |

### 3.7 Platform & system

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `service.started` | system | service | version, commit_sha |
| `service.stopped` | system | service | reason, signal |
| `service.deployed` | system | service | version, commit_sha, deployer, pr_url |
| `service.config.reloaded` | system | service | setting_paths |
| `db.user.created` | admin | db_user | purpose |
| `db.user.dropped` | admin | db_user | reason |
| `db.privilege.granted` | admin | db_user | privilege |
| `db.privilege.revoked` | admin | db_user | — |
| `kek.rotated` | system | tenant | tenant_id, key_version |
| `kek.disabled` | system | tenant | reason |
| `backup.started` | system | backup | target, type |
| `backup.completed` | system | backup | target, size, duration, status |
| `backup.failed` | system | backup | target, error |

### 3.8 Security-relevant system events

| Event type | Actor | Object | Disposition |
|---|---|---|---|
| `ids.alert` | system | event | rule_id, severity, asset |
| `malware.detected` | system | file | file_hash, scanner, asset |
| `process.suspicious` | system | process | rule_id, asset, process |
| `network.anomaly` | system | flow | rule_id, src, dst |
| `secrets.accessed` | user | secret | secret_ref, reason |
| `breakglass.activated` | user | scope | justification, ticket |
| `breakglass.deactivated` | user | scope | duration |

## 4. Record schema

Every audit record is a single JSON object with the following fields.
The schema is versioned via the `schema_version` field; consumers
**must** tolerate unknown fields and **must** be able to read at least
the previous two major versions.

```json
{
  "schema_version": "1.0.0",
  "id": "01HXXXXXXXXXXXXXXXXXXXXXX",        // ULID
  "ts": "2026-06-12T14:23:45.123Z",         // RFC 3339 ms-precision UTC
  "tenant_id": "tnt_abc123",                // null for platform events
  "event_type": "auth.login.success",
  "severity": "info",                       // info | notice | warning | alert | critical
  "actor": {
    "type": "user" | "service" | "agent" | "system" | "anonymous",
    "id": "usr_123",
    "session_id": "sess_456",
    "ip": "203.0.113.4",
    "user_agent": "Mozilla/5.0 ...",
    "geo": { "country": "US", "region": "CA" }   // best-effort, may be null
  },
  "object": {
    "type": "session",
    "id": "sess_456",
    "classification": "internal"            // public | internal | confidential | restricted
  },
  "action": "create",
  "disposition": "success",                 // success | failure | unknown
  "message": "Human-readable summary",
  "metadata": { /* event-specific */ },
  "trace": {
    "trace_id": "0af7651916cd43dd8448eb211c80319c",
    "span_id": "b7ad6b7169203331",
    "request_id": "req_789"
  },
  "source": {
    "service": "auth",
    "version": "1.4.2",
    "commit_sha": "9a3f1c0",
    "env": "prod",
    "region": "us-east-1",
    "az": "us-east-1a",
    "host_id": "hst_321"
  },
  "prev_hash": "sha256:abc...",             // hash of previous record in the stream
  "hash": "sha256:def..."                   // hash of this record (excluding `hash`)
}
```

### Field rules

- **id** is a ULID (lexicographically sortable, time-ordered).
- **ts** is set at the moment the event occurs, not when it's shipped.
- **tenant_id** is `null` for platform-internal events; required for any
  event that touches a tenant's data.
- **actor** MUST NOT contain plaintext credentials, tokens, or PII
  beyond what is needed for correlation (e.g., user_id is OK; an email
  address requires the `metadata` field and a documented use case).
- **object.classification** follows the data classification scheme.
- **trace** fields allow correlation with distributed traces and APM.
- **prev_hash / hash** implement a per-stream hash chain (see §6.3).
- **metadata** is event-specific; each event type's metadata schema is
  defined in the event registry.

## 5. Storage tiers

Audit records flow through three storage tiers:

| Tier | Storage | Retention | Access | Use case |
|---|---|---|---|---|
| **Hot** | Object storage index (per-tenant) + searchable SIEM | 13 months | Tenant-scoped read; auditor read | Live investigation, recent audit |
| **Warm** | Compressed object storage, queryable via Athena/equivalent | 7 years | Auditor + legal hold | Internal/external audit |
| **Cold** | Object storage with object lock, WORM | 7 years (configurable) | Two-person unlock; legal hold only | Regulatory requests, litigation |

### 5.1 Per-tenant isolation

Each tenant's audit records are stored in a tenant-scoped index and
prefix. Cross-tenant correlation is permitted **only** via the
explicitly authorized `auditor` and `compliance-officer` roles, and is
itself audited. See §7.

### 5.2 Encryption

- All audit records are encrypted at rest with AES-256 using tenant
  keys wrapped by the platform KMS.
- Encryption keys are rotated annually; rotation events are themselves
  audit-logged.
- The integrity hash chain (§6.3) is computed **before** encryption, so
  integrity can be verified without decrypting content.

## 6. Integrity and protection

### 6.1 Append-only

The audit storage is append-only at the storage layer. The only
operations supported are:

- **Append** — add a new record.
- **Read** — retrieve records (with auth).
- **Legal-hold** — pin records to prevent deletion even after retention
  expiry.

Deletion and modification are **not** supported. The only exception is
cryptographic erasure of a tenant's key on tenant off-boarding, which
renders the tenant's records cryptographically unreadable while
preserving the integrity chain for the rest of the system.

### 6.2 Object lock / WORM

Hot and warm tiers use cloud-native object lock in compliance mode.
The lock cannot be removed by any IAM principal, including the root
account, until the retention period expires. This protects against an
attacker who gains root credentials.

### 6.3 Cryptographic hash chain

Each record's `hash` is computed as `SHA-256(prev_hash || canonical_json(record_minus_hash))`.
The first record in a stream has `prev_hash = "sha256:" + 64_zeros`.

A daily **Merkle root** is computed per tenant (and per service for
platform events) and published to an immutable write-only log
("notary log") outside the audit store. The notary log itself is
hosted on a different cloud account and is independently monitored.

This structure means:

- Tampering with any record invalidates the chain and is detectable.
- The Merkle root is the cryptographic anchor; auditors can prove a
  record's inclusion in the daily root.
- A daily comparison between the computed root and the published root
  detects missing records.

### 6.4 Tamper detection

A scheduled job (every 15 min for hot, every 6 h for warm) re-verifies
the hash chain. A mismatch raises a `audit.integrity.violation` event,
which is itself logged (with the violation details) and pages the
on-call.

### 6.5 Confidentiality

Audit records may contain sensitive information (e.g., user IDs, IP
addresses, action descriptions). Access is restricted to the
`auditor`, `compliance-officer`, `security-admin`, and
`breakglass-compliance` roles. All access is itself audit-logged.

## 7. Access control

| Role | Read | Export | Configure retention | Legal hold | Notes |
|---|---|---|---|---|---|
| Tenant user (own tenant) | ✅ | ✅ | ❌ | ❌ | Via UI/API |
| Tenant admin (own tenant) | ✅ | ✅ | Configure for own tenant | ❌ | |
| Tenant auditor (own tenant) | ✅ | ✅ | ❌ | ❌ | Read-only API |
| Platform auditor (all tenants) | ✅ | ✅ | ❌ | ❌ | Justification required per query |
| Compliance officer (all) | ✅ | ✅ | ✅ | ✅ | |
| Security admin (all) | ✅ | ❌ | ❌ | ❌ | Forensics only |
| Breakglass-compliance | ✅ | ✅ | ❌ | ✅ | Two-person activation |
| On-call SRE | ❌ | ❌ | ❌ | ❌ | Access via break-glass |

### 7.1 Break-glass

The break-glass role requires:

1. Two-person activation (one to request, one to approve).
2. Justification text.
3. Time-boxed (default 4 hours, max 24 hours).
4. Auto-revocation on expiry.
5. Page to security on-call on activation.

The activation and deactivation are themselves audit-logged, and the
justification is stored immutably with the activation record.

## 8. Review and monitoring

| Activity | Frequency | Owner | Output |
|---|---|---|---|
| Automated anomaly detection | Real-time | SREEngineer | SIEM alerts |
| Privileged-action review (random sample) | Weekly | ComplianceOfficer | Review report |
| All break-glass activations | Within 24 h of activation | SecurityArchitect | Investigation |
| Failed-auth spike | Real-time | SREEngineer | SIEM alert |
| High-severity event review | Within 1 h | SecurityArchitect | Incident response |
| Audit log itself (chain integrity) | Every 15 min | SREEngineer | Integrity report |
| External audit (SOC 2 / ISO) | Annually | ComplianceOfficer | Auditor report |

### 8.1 Detection rules (minimum set)

The following SIEM rules are required at v1 GA:

1. Failed logins: > 5 in 5 min from same IP.
2. Successful login after N failures.
3. New geo for known user.
4. Privileged action outside change window.
5. Break-glass activation.
6. Audit chain integrity violation.
7. Bulk data export (> 10k records).
8. Service account use outside scheduled window.
9. Configuration change to security-relevant settings.
10. Disabled user account usage attempt.

## 9. Pipeline architecture

```
producer ──> local buffer (durable, on-disk)
          ──> shipper (Fluent Bit / Vector)
          ──> ingest (Kafka / Kinesis)
          ──> enrich + parse (validate schema, add geo, add classification)
          ──> compute hash chain + Merkle root
          ──> write to object storage (per-tenant)
          ──> index in SIEM (per-tenant index)
          ──> daily Merkle root → notary log
```

### 9.1 Local buffering

Producers buffer events on local disk (durable queue). If the downstream
pipeline is unavailable, the buffer absorbs up to 24 h of events. If the
buffer fills, the producer raises `audit.pipeline.backpressure` and
**fails closed**: any new privileged action that would normally produce
an event is rejected. This is a deliberate trade-off: a privileged
action without an audit record is never allowed.

### 9.2 Schema enforcement

Every event is validated against the event-type schema in the registry
before being emitted. Invalid events are dropped and a
`audit.event.invalid` alert is raised — the source is expected to fix
its emitter.

### 9.3 Cardinality protections

The audit log is not a metrics store. The following are *not* allowed
in audit records: free-form user-supplied strings in indexed fields,
high-cardinality tags, payload dumps. PII is stored only when required
for the event's purpose and is hashed where possible.

## 10. Customer evidence

The platform exposes audit data to customers in two ways:

1. **Self-service UI/API** — the Compliance service provides a
   tenant-scoped audit query UI and an API. Customers can build reports
   for their own auditors.
2. **Evidence bundles** — the platform generates signed JSON-LD evidence
   bundles for the controls in this document. Each bundle includes the
   relevant audit records, signed by the platform, and can be supplied
   to a customer's auditor.

Customer-facing audit access is itself audited.

## 11. Retention schedule

| Data class | Hot | Warm | Cold | Notes |
|---|---|---|---|---|
| Authentication events | 13 months | 7 years | 7 years | |
| Authorization events | 13 months | 7 years | 7 years | |
| Data access (PII) | 13 months | 7 years | 7 years | |
| Configuration change | 13 months | 7 years | 7 years | |
| Vulnerability / incident | 13 months | 7 years | 7 years | |
| Agent / integration | 13 months | 7 years | 7 years | |
| Platform events | 13 months | 7 years | 7 years | |
| Merkle roots (notary) | 7 years | — | — | Independent store |

Retention is configurable per tenant for non-regulatory classes, with
a floor of 13 months.

## 12. Open questions (Sprint 1)

1. Will the platform offer a customer-managed key option (CMK/BYOK) for
   the audit log? (Affects §5.2 — currently assumed but not built.)
2. Is the notary log on the same cloud as the platform, or on a
   different cloud? (For multi-cloud posture, a different cloud is
   preferred.)
3. Do we need to retain records for tenants that churn (e.g., 7 years
   post-off-boarding) for regulatory reasons?
4. Does the EU data residency requirement mandate a separate audit
   store in EU regions, with no cross-region copies?
