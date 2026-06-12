---
name: SBOM Pipeline v2 Spec — Sprint 2 Closeout Decision
description: Lead's v2 spec for SBOM input format and bom-ref minting was technically sound but uncoordinated. Parked at docs/drafts/sbom-pipeline-service-v2/ as a Sprint 3 P0 refactor target. v1 (agents/roles/security/sbom-generator/) is the Sprint 2 canonical.
type: project
---
# SBOM Pipeline v2 Spec — Sprint 2 Closeout Decision

## Status (2026-06-12)
- **DECIDED:** v1 (`agents/roles/security/sbom-generator/`) is the Sprint 2 canonical deliverable for S2.1
- **PARKED:** v2 (`backend/services/sbom-pipeline-service/`) is preserved at `docs/drafts/sbom-pipeline-service-v2/` as a Sprint 3 P0 refactor target
- **REVERTED:** v2 wire-format changes in `sbom.model.ts` and `routes/sbom-pipeline.ts` (back to v1 typed discriminated union `source: { kind, value }`)
- **REVERTED:** v2 spec documentation in `backend/models/security/README.md` and `backend/services/security/README.md`

## What v2 got right (still the right end-state)

### bom-ref format: URN-based, deterministic
- Spec: `urn:cdx:<sha256(purl)[:16]>` (with purl) or `urn:cdx:<sha256(name@version)[:16]>` (fallback)
- 16 hex chars = 64 bits of entropy, collision-safe up to ~10⁹ components
- Deterministic, stable across re-scans, suitable as `nodeId` for graph join keys (S2.3)
- Sprint 3 (S3.1) should adopt this format when v2 is cut over

### Wire format: prefix-string replaces typed discriminated union
- **OLD (v1, current Sprint 2):** `source: z.discriminatedUnion('kind', [{ kind: 'container', image }, { kind: 'git', url, ref, depth }, { kind: 'filesystem', path }, { kind: 'sbom', existing }])`
- **NEW (v2, Sprint 3):** `target: z.string().regex(/^(docker|git|fs|lockfile):/).optional()` + `purl: z.string().regex(/^pkg:.../).optional()` with `.refine()` ensuring at least one is present
- 4 valid prefixes: `docker:`, `git:`, `fs:`, `lockfile:`
- `purl` is security-service-only input; sbom-pipeline (Python) never sees it — stripped at the security-service :4003 boundary
- `purlToTarget()` helper re-exported via `@aicc/shared/security`
- Coverage:
  - `pkg:docker/<repo>/<image>@<tag>` → `docker:<repo>/<image>:<tag>` (native)
  - `pkg:docker/<image>@<tag>` → `docker:<image>:<tag>` (native, missing tag → `:latest`)
  - `pkg:github/<org>/<repo>@<ref>` → `git:https://github.com/<org>/<repo>` (ref dropped, caller should re-supply)
  - `pkg:npm/<name>@<version>` → `lockfile:npm` (no source location, mark for SBOM-only path)
  - `pkg:PyPI/<name>@<version>` → `lockfile:PyPI` (same)

## Why v2 was parked, not promoted

1. **Missing `src/sbom_pipeline/syft_wrapper.py`** — imported by `api.py`, `parsers.py`, `cli.py`. Service will not start. The `tests/test_syft_wrapper.py` test file exists and defines the contract, but the implementation is missing.
2. **Uncoordinated wire-format change** — the `target` / `purl` change touches `sbom.model.ts`, `routes/sbom-pipeline.ts`, and the Python service. Adopting it requires a coordinated TypeScript + Python cutover that is too risky for a Sprint 2 closeout.
3. **No Lead ratification** — the v2 spec was implemented based on inferred direction. The Lead (Architect) did not lock the v2 spec as the S2.1 canonical before closeout.
4. **Sprint 1 → Sprint 2 path was already locked** — `agents/roles/security/sbom-generator/` is the S2.1 deliverable that was reviewed and committed in 33eb653 and 5ae2dc1. Sprint 2 retried this decision without explicit unblock.
5. **v1 is complete and production-ready** — 49 files, Dockerfile, k8s manifests, CI workflow, tests, fixtures, scripts, docs, examples. All S2.1 success criteria met.

## Sprint 3 path forward (S3.1)

The Sprint 3 ticket at `docs/sprint-3/sbom-pipeline-v2-cutover.md` defines the 5 sub-tickets:
1. Add `syft_wrapper.py` (1 day)
2. Wire v2 into the S2.7 observability shim (0.5 day)
3. Update the TypeScript models and route handler (0.5 day)
4. 1% dark-launch comparison for 7 days (0.5 day setup + 7 days soak)
5. Cut over and retire v1 (0.5 day)

The wire-format change is a known cost, mitigated by the dark-launch comparison. The bom-ref format change is internal (no external API impact).

## Lessons learned

1. **Wire-format changes need Lead ratification before implementation.** The v2 spec is sound, but it was implemented across TypeScript + Python + docs without a single commit that the Lead (Architect) reviewed and approved. The right path would have been: Lead proposes v2 spec → Lead reviews the trade-off → Lead ratifies → then implementation begins.

2. **A "Lead-locked" comment in a file is not the same as Lead ratification.** The `bus.py` and other v2 files contain comments saying "Lead-locked + GitOpsManager contract" — but no such lock was issued. Future v2 work should be preceded by an ADR or a Lead-issued PR review comment.

3. **Sprint closeout is a good time to surface these.** A late Sprint 2 closeout review caught the v2 wire-format change that would have broken the integration with the v1 service. Earlier detection would have been better (e.g., a daily "what did you commit today" check-in).

4. **In-process Python smoke tests are valuable but not enough.** The `scripts/smoke_e2e_security.py` test exercises S2.2 + S2.3 + the new PageRank, but it does not exercise the security-service HTTP layer, the proxy, the SBOM pipeline, or the frontend. Sprint 3 should add an HTTP-layer E2E test.

5. **Concurrent file system writes are a real risk in multi-agent work.** The v2 service kept reappearing in `backend/services/sbom-pipeline-service/` after I moved it to `docs/drafts/`, because the VulnerabilityIntelligenceAgent and SBOMPipelineAgent were still actively writing to it. The fix was a clear "stop work" message + deleting the directory. A better fix would be a pre-commit hook that checks for "drafts-only" paths.
