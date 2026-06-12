---
name: s3-backlog-state
description: Sprint 3 backlog at close of Sprint 2 — 8 P0/P1/P2 tickets, v2 SBOM pipeline cutover as P0
type: project
---

Sprint 3 is planned to kick off 2026-06-15. Backlog lives at
docs/sprint-3/backlog.md (created during Sprint 2 closeout).

**Sprint 3 ceremonies (FullstackEngineer, confirmed 2026-06-12):**
- **Planning:** 2026-06-15 (Mon) 1h, all agents
- **Daily standup:** async via `team_send_message`
- **Mid-sprint check-in:** 2026-06-19 (Fri)
- **Review + retro:** 2026-06-26 (Fri)
- **Mission brief:** Lead circulates Sunday 2026-06-14 evening

**4 T-03 follow-up flags from SecurityArchitect (filed 2026-06-12, Sprint 3 candidates):**
- T-03.1: clamp band math = T-04 attack surface (adversarial input floor)
- T-03.2: decouple `clamp_applied` / `human_review_routed` flags (invariant)
- T-03.3: `vuln_intel_pre_actionable` 3-state enum (not `bool | None` in Loki)
- T-03.4: JSON Schema SSoT (with PlatformArchitect + VulnerabilityIntel)

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

**Additional Sprint 3 tasks filed on board (post-closeout, owned by GitOpsManager):**
- `019ebc2b-…` S3.1 cap-sizing review infra: dashboard panel + recording-rule export (GitOps deliverable for SecurityArchitect + SRE's cap-sizing validation)
- `019ebc2b-…` S3.x F-14 PG schema: audit_log append-only + 7-yr retention + WORM (GitOps review + land) — cross-compat with Sprint 2.1 F-14 PR is confirmed: additive DDL delta is forward-compatible
- `019ebc2b-…` S3.x Alertmanager routing for S2.9 audit-emission alerts (GitOps land) — SRE's alerts, GitOps lands the routing config
- `019ebc2d-…` S3.x VULN_INTEL_AUTO_ACTION_EPSS_MIN + SECURITY_AUTO_ACTION_EPSS_MIN env var pair (default 0.36, coordinated) — relates to P2 4-condition `auto_actionable` formula's EPSS branch; coordinated env var design is GitOps-owned, both consumers (vuln-intel Python, security-service Node) read it

**Backlog hygiene note:**
The Sprint 3 backlog file should be re-verified for any items added
by the ComplianceOfficer's Sprint 2.1 follow-ups (mapping-engine
extension, evidence attacher, scan listener, mapping rules update,
F-17 PR). If the ComplianceOfficer added items in their TURN 2-5
follow-ups that were deferred to Sprint 3, those need to be
consolidated into the backlog before kickoff.

**Broader Sprint 3 scope (from `docs/sprint-3/backlog.md`, NOT Sprint 2 carry-over):**
- S3.2: Live Trivy + Dependency-Track integration (VulnerabilityIntelligenceAgent, P1)
- S3.3: Agent runtime v1 (PlatformArchitect, P1)
- S3.4: WebSocket real-time channel for the security dashboard (FullstackEngineer, P2)
- S3.5: Helm chart for the AionRs security stack (SREEngineer, P1)
- S3.6: Terraform landing zone (SREEngineer, P2)
- S3.7: Compliance evidence auto-collection (ComplianceOfficer, P1)
- S3.8: Risk score explainability SHAP-style (DataScientist TBD, P3)
