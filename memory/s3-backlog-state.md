---
name: s3-backlog-state
description: Sprint 3 backlog at close of Sprint 2 — 8 P0/P1/P2 tickets, v2 SBOM pipeline cutover as P0
type: project
---

Sprint 3 is planned to kick off 2026-06-15. Backlog lives at
docs/sprint-3/backlog.md (created during Sprint 2 closeout).

**P0 (must-have):**
- S3.1: v2 SBOM pipeline cutover — the v2 service is COMPLETE at
  docs/drafts/sbom-pipeline-service-v2/sbom-pipeline-service/ (27
  files: 13 src .py including syft_wrapper.py, 4 test files, 8
  config files: Dockerfile, Makefile, README, CHANGELOG, .gitignore,
  .dockerignore, .env.example, pyproject.toml). 69/69 tests pass per
  the SBOMPipelineAgent. Cutover decision: which service becomes
  canonical, the v1 (Sprint 2) or v2 (now complete)?
  - v1 SBOMGenerator: agents/roles/security/sbom-generator/src/sbom_generator/
  - v2 (parked then completed): docs/drafts/sbom-pipeline-service-v2/sbom-pipeline-service/

**P1 (should-have):**
- S3.2: ComplianceOfficer F-17 PR — adapter, scan-listener update,
  mapping-rules update, tests, compliance-mapping.md §5.3.
- S3.3: F-14 audit log store wiring (option B): direct
  AUDIT_LOG_TOPIC subscriber. P5 task 019ebc1a-3468 is the
  implementation owner (ComplianceOfficer, ~120 LOC).
- S3.4: D6 tenant_tier recording-rule pre-aggregation
  (~230k → ~30k series reduction).
- S3.5: SRE observability-{py,ts}/audit.py/audit.ts platform helpers.

**P2 (nice-to-have):**
- S3.6: F-1 burn-rate alerts (TODO block already in alert-rules.yml).
- S3.7: F-20 event-shape reshape (parallel arrays → rich
  affected: AffectedPackage[]).
- S3.8: Widen VulnKind to add dast/manual when a scanner emits them
  on the wire (one-line Zod schema change).

**Backlog hygiene note:**
The Sprint 3 backlog file should be re-verified for any items added
by the ComplianceOfficer's Sprint 2.1 follow-ups (mapping-engine
extension, evidence attacher, scan listener, mapping rules update,
F-17 PR). If the ComplianceOfficer added items in their TURN 2-5
follow-ups that were deferred to Sprint 3, those need to be
consolidated into the backlog before kickoff.
