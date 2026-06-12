---
name: S2.10 GitOps Wire-Format Alignment (FullstackEngineer ↔ GitOpsManager)
description: Three gaps identified between security-service :4003 emit code and GitOpsManager's locked NDJSON contract in security/README.md + runbook. Topic names, per-finding explosion, snake_case field alignment, missing auto_actionable/git_sha/detected_at. Holding code changes pending GitOpsManager sign-off.
type: project
---

# S2.10 — GitOps Wire-Format Alignment (security-service :4003 ↔ GitOpsManager)

## Context
- GitOpsManager LANDED S2.10 (8 commits on main) on 2026-06-12.
- Folder contract: `security/README.md`. Runbook: `docs/runbooks/security-automation.md`.
- Auto-committer listens to Redis Stream subject `security.vulnerability.detected.v1` (explicit in runbook line 48).
- I (FullstackEngineer) own security-service :4003 which emits to the bus. I must align my emit shape to GitOpsManager's wire contract.

## Gap 1 — Topic names (.v1 suffix missing in my code)
- My `topics.ts` has bare names: `security.sbom.generated`, `security.vulnerability.detected`, `security.risk.calculated`
- Contract uses `.v1` suffix
- **Proposed fix:** add `.v1` to all three. Single PR, 3 lines. Non-breaking (no events emitted yet).

## Gap 2 — Wire format is per-FINDING, my schema is per-CVE
- GitOps NDJSON record is per-(CVE, package) pair
- My `VulnerabilitySchema` is per-CVE with `affected: Array<...>` (one CVE → many packages)
- **Proposed architecture:**
  - Keep `VulnerabilitySchema` as internal rich model (epss/kev/descriptions/aliases)
  - Add `VulnerabilityGitOpsRecordSchema` (strict wire subset, snake_case, single `package`)
  - Project at security-service :4003 route boundary
  - Or: push projection down to vuln-intel :4008 (awaiting GitOpsManager choice)

## Gap 3 — Field-by-field alignment matrix
| GitOps field (snake_case, wire) | My field (camelCase, internal) | Status | Action |
|---|---|---|---|
| `id` | `id` | ✅ | none |
| `source: "osv\|nvd\|github-advisory\|snyk"` | `source: "nvd"\|"ghsa"\|"osv"\|"snyk"` | ⚠️ ghsa≠github-advisory | project ghsa→github-advisory |
| `severity` (lowercase enum) | same | ✅ | none |
| `cvss_v3: number` (flat) | `cvssV3: {baseScore, vector, version}` (object) | ⚠️ shape | project to baseScore |
| `package: string` (flat) | `affected[].name` (per-entry) | ⚠️ granularity | explode on affected[] |
| `ecosystem: string` (top-level) | `affected[].ecosystem` (per-entry) | ⚠️ granularity | explode on affected[] |
| `introduced_in: string` | (missing) | ❌ | add `introducedIn` to affected[] |
| `fixed_in: string[]` (array) | `fixedVersion: string \| null` (single) | ⚠️ singular | rename to `fixedIn: string[]` (or deprecate fixedVersion) |
| `vulnerable_range: string` | `versionRange: string` | ⚠️ casing | rename to `vulnerableRange` (camelCase internal) |
| `summary: string` | `descriptions[0].value` (object array) | ⚠️ shape | project to first description's value |
| `references: string[]` (URLs) | `references: [{url, type, tags?}]` | ⚠️ shape | project to URL strings |
| `detected_at: string` (when WE detected) | `lastModifiedAt` (upstream's) | ❌ semantics | add `detectedAt: string` |
| `git_sha: string` | (missing) | ❌ | add `gitSha: string \| null` |
| `auto_actionable: boolean` | (missing) | ❌ **REQUIRED** for critical-CVE escalation | add `autoActionable: boolean` (default false; true = known-exploited + fix-available) |

## Recommendation: keep camelCase internally, project to snake_case at wire boundary
- JS-ecosystem friction minimized
- Single source of projection logic
- Easy to add v2 schemas later
- GitOpsManager to confirm or override

## Open questions awaiting GitOpsManager
1. Topic names: OK to add `.v1` suffix?
2. Per-finding explosion: where does projection live (security-service :4003 route boundary, or vuln-intel :4008)?
3. Field renames: keep camelCase internally + project at boundary, or rename throughout?
4. `ghsa` → `github-advisory` enum mapping: project at boundary, or rename?
5. `auto_actionable` default `false`; `true` for known-exploited + fix-available — confirm
6. Add `kind: "sca"|"sast"|"runtime"|"container"|"iac"` to wire format? (forward-looking; Sprint 2 emissions all `sca`)

## Code changes pending sign-off (estimated <2h)
- `backend/packages/shared/src/security/topics.ts` — add `.v1` to 3 constants + new `kind` field on typed events
- `backend/models/security/vulnerability.model.ts` — add `autoActionable`, `gitSha`, `detectedAt` + new `VulnerabilityGitOpsRecordSchema`
- `backend/services/security/src/services/vuln-projection.ts` (NEW) — projection helper, ~30 lines
- `backend/services/security/src/routes/vulnerabilities-ingest.ts` — project on emit (explode on affected[])
- `backend/services/security/src/services/event-log.ts` — log the GitOps record shape
- `backend/services/security/README.md` — document the wire format
