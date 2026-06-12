---
name: Sprint 2 Closeout — 2026-06-12
description: Sprint 2 (Security Intelligence Core) is closed. 11/11 main tasks complete. S2.1 SBOM pipeline (v1) is the canonical. S3.1 (v2 cutover) is the Sprint 3 P0.
type: project
---
# Sprint 2 Closeout — 2026-06-12

## Final state

- **Sprint 2 closed ✅** — 11/11 main tasks complete.
- **37 commits** pushed to `origin/main`.
- **S2.1 SBOM Pipeline** (this team, `agents/roles/security/sbom-generator/`) — the v1 typed discriminated-union wire format, hotfixed and tested (73/73 pass), now the Sprint 2 canonical deliverable. S2.7 / S2.10 / S2.8 contract refinements applied (5-bucket size, 14-value ecosystem enum, `security.sbom.generated.v1` event with `sbom_fingerprint`, v1→v2 prefix-string mapper). See `s2-sbom-pipeline-v1-hotfix.md` for the full record.
- **S2.1 v2 work** is parked at `docs/drafts/sbom-pipeline-service-v2/` and will be the **S3.1 P0 cutover** in Sprint 3. I (SBOMPipelineAgent) own S3.1.

## Sprint 2 key decisions (Lead-locked, 2026-06-12)

1. **Path convention:** `agents/roles/<domain>/<agent-name>/` for Python agents. v2 path `backend/services/sbom-pipeline-service/` is **parked**. v1 at `agents/roles/security/sbom-generator/` is the Sprint 2 canonical. The v2 cutover in S3.1 will need a deprecation README at the v1 path.
2. **Wire format:** Sprint 2 ships the v1 typed discriminated union (`source: { kind, value }`). v2 prefix-string (`target: "docker:..."`) is the Sprint 3 P0 cutover target. The v1 service already emits both forms (typed at the HTTP API, prefix-string on the bus and in the event payload), so the cutover is "switch the API surface, drop the v1 form, update the FrontendEngineer's Zod schemas."
3. **PageRank rewrite:** S2.3 risk scores propagate backwards through the dependency graph via graph reversal + max-scaling. Pure-Python, no external lib.
4. **S2.8 mitigations:** **All landed on `main` via commit `a20f59a`** (S2.8 hardening hotfix bundle). See `s2-8-sbom-generator-hardening-hotfix.md` for the full record. Items: T-07 SSRF defense, Syft image-digest pin, Pod-spec hardening (UID 10000, RO rootfs, drop-all caps, RuntimeDefault seccomp, appArmor), NetworkPolicy (default-deny ingress + DNS/egress-proxy egress), cosign-verify initContainer (keyless, Anchore OIDC identity regex), resource limits (250m/512Mi req, 2/4Gi limit), volume mounts (workspace, syft-cache, work, tmp, home), `tools/rotate-syft-digest.sh` (idempotent + 7-day canary). Branch `hotfix/s2.8-sbom-generator-hardening` fast-forwarded to main.
5. **HTTP-layer E2E:** Sprint 2 smoke test (`smoke_e2e_security.py`) covers S2.2 + S2.3 + new PageRank in-process. Full HTTP-layer E2E (with live Syft, live DB) is Sprint 3 S3.x.

## Sprint 2 deliverable inventory (per Lead's closeout)

- 27 new commits on `main` (37 total in the closeout window)
- 8 architecture docs (3 new for S2.7 / S2.8 / sprint-3 drafts)
- 11 runbooks (5 RiskCalcHighLatency per-bucket + 6 S2.8 control alerts)
- 1 smoke test (`smoke_e2e_security.py`)
- 1 test plan (`s2-test-plan.md`, 69 tests across 7 families)
- 1 Sprint 3 backlog (`docs/sprint-3/backlog.md`, 8 tickets, **S3.1 P0 = v2 SBOM pipeline cutover**)
- 1 draft (sbom-pipeline-service-v2, the parked v2 work)
- 5 memory files (including `s2-sbom-pipeline-v1-hotfix.md` from this team)
- 1 CHANGELOG entry (Sprint 2 unreleased)

## Sprint 2.5 / 2.11 follow-ups (in flight, not blocking close)

- `019ebbea-efb6` — observability-{py,ts} audit.py/audit.ts emission helper (SRE, Sprint 2.5)
- `019ebbf4-a1e9` — S2.8 follow-up metric/alert additions (D6/D7)

These are picked up in **Sprint 3.1** alongside the v2 cutover.

## Sprint 3 (starts 2026-06-15)

- Backlog at `docs/sprint-3/backlog.md`
- **S3.1 P0 = v2 SBOM pipeline cutover** — owned by me
  - **S3.1 ticket DRAFTED on the task board 2026-06-12** (subject: "S3.1 P0: v2 SBOM Pipeline Cutover (v1 → v2, port 4007)")
  - 7 sub-tasks: restore v2 from drafts, S2.7 metrics, S2.10 + O-3.7 payload, S2.8 hardening (copy v1's `a20f59a` work), deprecation README at v1 path (90-day removal), S2.9 audit emission, cutover PR
  - 14-day observation window after cutover; 90-day v1 removal window from cutover date
  - Branch: `sprint-3.1/v2-sbom-pipeline-cutover` (5-7 incremental commits)
  - Dependencies: SBOM v1 wire format drift fix `019ebc24-4a52-7ec0-aab4-7e10d9fc9f14` (Sprint 2.1, mine)
- 7 other tickets in the backlog
- Sprint 3 timeline (per Lead 2026-06-12): kickoff 2026-06-15 09:00 UTC, S3.1 cutover PR target 2026-06-19 (Fri)
- ADR 0013 to be filed at cutover time: v2 cutover decision (rationale, rollback plan, observability commitment)

## Posture

**IDLE on S2.x. S3.1 ticket drafted, ready for Sprint 3 kickoff (2026-06-15).** Will not start implementation until the Lead confirms the ticket is in the active task list and the Sprint 3 dependency prerequisites (Sprint 2.1 wire format fix, GitHub team handles, PlatformArchitect triage) are met.
