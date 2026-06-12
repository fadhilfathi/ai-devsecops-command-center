---
name: S2.5 SBOM v1 Wire Format Drift Fix (O-3.7 alignment) — 2026-06-12
description: Sprint 2.5 hotfix aligning SBOM agent's runtime event payload with O-3.7 LOCKED JSON Schema at security/wire-format/sbom-generated.schema.json. Commit b7413e3 on main. 4 drift items fixed + 3 missing fields + 1 invalid field. Path A: next hotfix batch.
type: project
---
# S2.5 SBOM v1 Wire Format Drift Fix (O-3.7 alignment)

## Why this exists

GitOpsManager (slot `019ebae2-9e25-7970-952c-4236216ff0d5`) flagged
4 wire format drift items in the SBOM agent's runtime event payload
that would block Sprint 2.1 P2 (`019ebc0c-…` FullstackEngineer's
O-3.7 Zod alignment) from passing
`tests/contracts/sbom-generated.contract.spec.ts`. The drift was
between the v1 runtime's emitted payload and the O-3.7 LOCKED JSON
Schema at `security/wire-format/sbom-generated.schema.json`.

The drift happened because the prior commit `2e85a86` (claimed
"O-3.7 wire format alignment") added the fingerprint fields
(algorithm + format) but did NOT rename the existing `format` /
`component_count` / `git_sha` fields. The `additionalProperties: false`
in O-3.7 means the old field names now fail validation.

## Path A chosen (per GitOpsManager recommendation)

> "Next hotfix batch (recommended): keeps the fix atomic with the
> field-add work you just did; single PR is easier to review."

Single PR: `b7413e3`. Branch: `hotfix/s2.5-sbom-wire-format-drift`
landed on `main` via the team's auto-commit flow.

## What's in the fix

### 1. O-3.7 wire format alignment (the blocker)

| Old (drift) | New (O-3.7) | Why |
|---|---|---|
| `format: "cyclonedx-json"` | `sbom_format: "cyclonedx-json"` | Field name. Schema enum is `cyclonedx-json \| spdx-json`. |
| `component_count: 247` | `components_count: 247` | Field name. SRE's `sbom_size_bucket` reads `components_count` (D1 verdict). |
| `git_sha: "a1b2..."` | `subject_fingerprint: "a1b2..."` (scope-aware) | Semantic. `subject_fingerprint` is git SHA for monorepo/git-tree, image digest for container, content hash for fs. |
| `sbom_fingerprint_format: "cyclonedx-json"` | `sbom_fingerprint_format: "cyclonedx-json+canonicalized-jcs"` | Enum value. The O-3.7 enum encodes format + canonicalization together. |
| (missing) | `sbom_path` | O-3.7 required. Scope-aware: relative repo path for git, OCI ref for container, fs path for filesystem. |
| (missing) | `subject` | O-3.7 required. Opaque ref: `repo:github.com/aionrs/api`, `docker:anchore/syft:v1.6.0`, `fs:/workspace/...`. |
| (removed) | (removed) | `source` was in v1 prefix-string form (`docker:anchore/syft:v1.6.0`). NOT in O-3.7 schema. `additionalProperties: false` rejects it. The semantics live in `subject` now. |

### 2. Model additions

`GenerateRequest`:
- `scope: Optional[str]` — 6-value enum: monorepo, service, package, container, git-tree, fs. Pydantic validator.
- `subject_fingerprint: Optional[str]` — caller-supplied fingerprint for the subject
- `subject_path: Optional[str]` — relative repo path for git-backed scans (folder contract)

### 3. Helper functions in `agent.py`

- `_o37_scope_value(request)` — derive scope from request or source kind
- `_o37_subject(request)` — opaque reference: `repo:`, `docker:`, `git:`, `fs:`, `registry:`, `unknown:`
- `_o37_subject_fingerprint(request, sbom_fingerprint, git_sha)` — scope-aware fingerprint
- `_o37_sbom_path(request)` — scope-aware path
- `_o37_format_value(format_str)` — map to O-3.7 enum (cyclonedx-json | spdx-json)

### 4. Contract tests (forcing function for future drift)

- `test_request_model.py::test_o37_payload_complies_with_schema` — loads the LOCKED JSON Schema and validates a synthetic payload (skips when schema/jsonschema not present in CI)
- `test_request_model.py::test_o37_payload_rejects_drifted_field_names` — regression test for the 4 drift items

## SecurityArchitect's 4 cross-checks + 6 T-07 refinements (also in this PR)

### Test inventory (cross-check #1)
- 8 → 11 SS-07 test cases. Added: SS-07k (SCP-style private IP `git@10.0.0.1:o/r.git`), SS-07l (`metadata.aws.internal`), SS-07m (`instance-data.ec2.internal`).

### Canary rollback (cross-check #2 / refinement #4)
- `tools/rotate-syft-digest.sh` — added `--rollback --to <sha256:...>` and `--abort` flags
- Abort conditions documented in script header: SS-01..SS-07 failure, scan error rate > 2× baseline for 15 min, P0 alert in `service.standard`
- Promotion gate: 10% → 50% after 24h; 50% → 100% after another 24h

### Syft `--override-hostname` (cross-check #3 / refinement #5)
- Verified: not exposed on v1 CLI surface
- The SSRF defense runs BEFORE the Syft subprocess is invoked (`SBOMGeneratorAgent._ssrf_check` between `request.validate_source()` and `self._runner.run(...)`)
- User input never reaches Syft directly. Clean.

### SSRF warnings metric (cross-check #4 / refinement #6)
- `devsecops_sbom_ssrf_warnings_total{warning_type, result}` counter wired on every `_ssrf_check` call
- Labels: `warning_type ∈ {dns_rebinding, blocklist, allow_no_resolved_addresses, allow_resolves_to_metadata}`, `result ∈ {deny, allow_with_warning}`
- **Filed to SRE for F1 burn-rate alert (S3.1 candidate)**
  - "ssrf warnings rate > 0.1/s for 15 min" → ticket
  - "ssrf warnings rate > 1/s for 5 min" → page
- The `result=allow_with_warning` label is the SRE F1 canary: it fires when the SSRF defense ALLOWS a request but the resolution was suspicious (e.g., resolved addresses include a cloud-metadata IP).

### T-07 refinements 1-5
- (1) AWS IMDS hostnames added: `metadata.aws.internal`, `metadata.google`, `metadata.azure`, `metadata.service.network`, bare `metadata` (legacy IMDSv1 fallback)
- (2) SS-07j: SCP-style form rejection (covered above)
- (3) CNAME chain walk: `resolve_and_check` returns ALL A/AAAA from `getaddrinfo`; every one is classified. Full CNAME chain walk is a Sprint 3 follow-up if Syft's resolver changes.
- (4) Rollback trigger: covered above
- (5) Syft `--override-hostname`: covered above

## Cross-team follow-ups

| Team | Task | Sprint |
|---|---|---|
| SRE | F1 burn-rate alert on `devsecops_sbom_ssrf_warnings_total{warning_type="dns_rebinding"}` | 3.1 |
| SRE | F1 burn-rate alert on `devsecops_sbom_ssrf_warnings_total{result="allow_with_warning"}` | 3.1 |
| FullstackEngineer | O-3.7 Zod alignment PR unblocked (`019ebc0c-…`) | 2.1 P2 |
| SecurityArchitect | S2.8 cap enforcement verification (5,000-component limit, unblocked) | 3.1 |
| GitOpsManager | Sprint 2 GitOps thread re-closable | 2.5 |
| Lead | Sprint 2.5 closeout (5-bucket + wire format drift = 2 in-flight fixes) | 2.5 |

## Files changed (this PR)

- `agents/roles/security/sbom-generator/src/sbom_generator/agent.py` — 5 helper functions, event payload alignment, SSRF warnings counter, AWS IMDS hostname handling
- `agents/roles/security/sbom-generator/src/sbom_generator/models/request.py` — `scope`, `subject_fingerprint`, `subject_path` fields + Pydantic validator
- `agents/roles/security/sbom-generator/src/sbom_generator/security/ssrf.py` — added AWS IMDS hostnames to blocklist
- `agents/roles/security/sbom-generator/tools/rotate-syft-digest.sh` — `--rollback` and `--abort` flags
- `agents/roles/security/sbom-generator/tests/test_request_model.py` — SS-07k/l/m, O-3.7 compliance + drift regression tests

## Notes for myself

- The drift happened because the prior commit `2e85a86` (claimed "O-3.7 wire format alignment") added the fingerprint fields but didn't rename the existing `format` / `component_count` / `git_sha` fields. Same spec-vs-review-drift pattern the SRE caught in their own reviews. Process gate (already in place per the 5-bucket fix): any change to a label vocabulary in the S2.7 spec triggers a `git diff` check across all emission sites BEFORE the spec amendment closes. The wire format alignment was a DIFFERENT drift (field name + value, not label vocabulary) — need a similar process gate for the O-3.7 schema amendments.
- The runtime is now the source of truth for the O-3.7 wire format. The JSON Schema is the spec. The Zod in the Frontend is the consumer's safety net. Any of these three can drift; the contract test `test_o37_payload_complies_with_schema` is the forcing function that catches it.
- The `_o37_subject_fingerprint` falls back to a content-derived fingerprint for `container` scope when only a tag is provided. The actual image digest lands in the sibling `provenance_path` artifact (written by the GitOps auto-committer) for Sprint 3 reconciliation.
- The `devsecops_sbom_ssrf_warnings_total` counter uses the `devsecops_*` prefix per D7 spec §3.1. The `result` label is `{deny|allow_with_warning}` — partition by this for the F1 alert to differentiate probing from attacks.
- The S2.8 cap enforcement verification (`019ebc36-5bfb-…`) is unblocked. The 5,000-component cap is in the same middleware as the SSRF defense. SecurityArchitect can now verify it's enforced.
- Sprint 2 GitOps thread re-closable from the wire format side. Boundary + single-writer invariant ACKed in the previous turn.
