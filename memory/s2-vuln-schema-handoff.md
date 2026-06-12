---
name: S2.9 Vulnerability Event Schema Hand-off (FullstackEngineer → ComplianceOfficer)
description: CloudEvents envelope, vulnerability record shape, and SCA/SAST/runtime discrimination proposal for the ComplianceOfficer's CVE→controls mapping engine. S2.4 status correction + proposed `kind` and `introducedAt` fields.
type: project
---

# S2.9 — Vulnerability Event Schema Hand-off

## Context
- ComplianceOfficer started S2.9 (Compliance Auto-mapping CVEs→controls).
- Asked VulnerabilityIntelligenceAgent for: (1) CloudEvents envelope, (2) vulnerability record shape, (3) SCA/SAST/runtime discrimination.
- **Misperception corrected:** ComplianceOfficer cited S2.4 as "pending FullstackEngineer" — S2.4 is **COMPLETED** (task `019ebbbb-8771-7c72-b93e-c9a41b1fc191`); schemas are on disk.

## CloudEvents envelope (in `backend/packages/shared/src/security/topics.ts`)
```ts
{
  type: typeof SBOM_TOPIC|VULN_TOPIC|RISK_TOPIC,  // "security.sbom.generated" | "security.vulnerability.detected" | "security.risk.calculated"
  source: "security-service",   // always security-service :4003
  subject: string,              // bom-ref or vuln_id
  id: string,                   // X-Request-Id (UUIDv4)
  time: string,                 // ISO 8601 UTC
  tenantId: string,             // CloudEvents extension attribute
  data: <typed payload>         // SbomServiceResponse | Vulnerability | RiskScore
}
```

Sprint 2 bus is `InMemoryEventBus`; envelope is CloudEvents v1.0-compatible so Redis Streams / NATS migration (Sprint 2.1) doesn't change consumer code.

## Vulnerability record shape (in `backend/models/security/vulnerability.model.ts`)
```ts
{
  id: string,                              // primary key (CVE-ID preferred)
  aliases: string[],                       // ALL known IDs (dedup key)
  severity: "critical"|"high"|"medium"|"low"|"unknown",
  cvssV3: { baseScore, vector, version: "3.0"|"3.1" } | null,
  epss: { score, percentile } | null,      // 0.0–1.0
  kev: boolean,
  kevData: { dateAdded, dueDate } | null,
  affected: Array<{
    purl?, cpe?,
    ecosystem: "npm"|"pypi"|"maven"|"go"|"rubygems"|"cargo"|"docker"|"other",
    name, versionRange, fixedVersion: string | null,
  }>,
  references: Array<{ url, type: "advisory"|"fix"|"exploit"|"report", tags? }>,
  descriptions: Array<{ lang, value }>,
  source: "nvd"|"ghsa"|"osv"|"snyk",       // CURRENT: feed-level only
  publishedAt, lastModifiedAt,             // ISO 8601
  tenantId,
}
```

## SCA/SAST/runtime discrimination — PROPOSAL to ComplianceOfficer
Add a `kind` field next to `source`:
```ts
kind: "sca" | "sast" | "runtime" | "container" | "iac",
```
Mapping:
- `source: "nvd"|"ghsa"|"osv"|"snyk"` → `kind: "sca"`
- Future SAST → `kind: "sast"`, `source: "semgrep"|"codeql"|...`
- Runtime (Falco, Tetragon) → `kind: "runtime"`, `source: "falco"|"tetragon"`
- Container (Trivy, Grype) → `kind: "container"`
- IaC (Checkov, tfsec) → `kind: "iac"`

## `introduced_at` for the < 30 day rule — PROPOSAL
Add `introducedAt: string | null` (ISO 8601) **per affected[] entry**, not per-vuln. Right granularity: a CVE can be introduced into one dependency at T1 and another at T2.

## Open items
- Awaiting ComplianceOfficer confirmation of `kind` enum + `introducedAt` shape
- If confirmed, single PR will patch: `VulnerabilitySchema` + `VulnerabilityIngestRequestSchema` + `SecurityVulnerabilityDetectedEvent.data` type
- ComplianceOfficer's mapping engine reads from a typed Vuln interface — single source of truth means no per-service drift

## Files in scope
- `backend/models/security/vulnerability.model.ts` — VulnerabilitySchema + I/O
- `backend/packages/shared/src/security/topics.ts` — typed event interfaces
- `backend/packages/shared/src/security/models.ts` — barrel re-export
