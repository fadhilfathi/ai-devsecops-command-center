---
name: S2.9 SCAN_TOPIC + assetId + kind (FullstackEngineer → ComplianceOfficer)
description: Added SCAN_TOPIC='security.scan.completed' + SecurityScanCompletedEvent; added optional assetId to all 3 existing events; added kind discriminator to VULN_TOPIC; documented topic-naming convention. 1 open question for ComplianceOfficer (introducedIn vs introducedAt vs both).
type: project
---

# S2.9 — SCAN_TOPIC + assetId + kind (ComplianceOfficer alignment)

## Context
- ComplianceOfficer (S2.9) needed typed `SCAN_COMPLETED` event shape + assetId on existing events + kind discriminator
- Also wanted topic-naming convention reconciled (`security.*` + `security-service` source)
- FullstackEngineer implemented 3 of 4 asks; 1 design question (introducedIn vs introducedAt) flagged back

## Code landed (`backend/packages/shared/src/security/topics.ts`)
- **Added `SCAN_TOPIC = 'security.scan.completed'`** (matches `security.*` + reverse-DNS prefix per ComplianceOfficer's spec)
- **Added `SCAN_TOPIC` to `SECURITY_TOPICS`** (so the bus knows about it)
- **Added `assetId?: string` to all 3 existing events** (additive, non-breaking back-compat)
  - `SecuritySbomGeneratedEvent.assetId?: string`
  - `SecurityVulnerabilityDetectedEvent.assetId?: string`
  - `SecurityRiskCalculatedEvent.assetId?: string`
- **Added `kind?: 'sca' | 'sast' | 'runtime' | 'container' | 'iac'` to `SecurityVulnerabilityDetectedEvent`** (S2.9; default 'sca' if absent)
- **Added new `SecurityScanCompletedEvent` interface** with all of ComplianceOfficer's requested fields:
  - `scanId`, `assetId` (REQUIRED), `tenantId`, `scanner` (8 enum values), `findings: Vulnerability[]`, `sbom?` (raw CycloneDX JSON), `scanReport?` (raw scanner report), `firstSeenAt?`, `detectedAt`, `source` (4 emitter enums)
- **Documented topic-naming convention** in topics.ts header (prefix `security.*`, source `security-service`, shape `<domain>.<aggregate>.<event>`, `.vN` versioning pending GitOpsManager)
- **Migrated** from old `import("@aicc/shared/security").X` references to direct imports from `models/security/vulnerability.model.ts` (cleaner, no circular)

## Design decisions made
1. **SCAN_TOPIC `subject` = assetId** (per CloudEvents spec, the subject IS the principal of the event)
2. **SCAN_TOPIC data-level `source` = scanner** (e.g., 'trivy'), bus envelope `source` = emitter (e.g., 'security-service') — separation matters because Python agents proxy multiple scanners
3. **Security-service does NOT emit SCAN_TOPIC yet** — defined the type only; Sprint 2.1 has Python agents emit it directly (cleaner than synthetic emission from the proxy)
4. **Asset id is OPTIONAL on existing 3 events** (back-compat) and REQUIRED on SCAN_TOPIC (new event)

## Files NOT modified (Sprint 2.1 work)
- Request schemas (`SbomGenerateRequest`, `VulnerabilityIngestRequest`, `RiskCalculateRequest`): no `assetId` field yet
- Route handlers: don't extract `assetId` from requests yet
- Python agents: don't emit `SCAN_TOPIC` yet

## Open question for ComplianceOfficer
`introducedIn` vs `introducedAt` vs both on `VulnerabilitySchema.affected[]`:
- (A) `introducedIn: string | null` (per-version-chain: when the vuln became applicable to this version)
- (B) `introducedAt: string | null` (per-deploy: when the package first appeared in the repo)
- (C) Both fields (more data, but explicit)

My pick: (C) both. Different rules need different semantics. Freshness rule (NIST-SI-7) needs `introducedAt`; attribution rules need `introducedIn`.

## Tenant isolation — CONFIRMED, no change needed
Security-service stamps `tenantId` at insert from `req.user!.tenantId` (JWT-authenticated), NOT from upstream feed. Matches POA&M multi-tenant isolation requirement.

## ComplianceOfficer's coordination plan (pending their confirm)
- Update `scan-listener.ts` to consume typed `SecurityScanCompletedEvent`
- Add `vulnerability-adapter.ts` (Vulnerability[] → NormalizedFinding[] with `kind` + per-affected `introducedIn/At`)
- Update `mapping-rules.json` to use new `kind` values
- Add unit test for the adapter
