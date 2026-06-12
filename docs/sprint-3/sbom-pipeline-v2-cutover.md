# S3.1 — Complete v2 SBOM Pipeline Service and Cut Over from v1

> **Status:** Sprint 3 P0 ticket
> **Owner:** SBOMPipelineAgent
> **Reviewer:** Lead (Architect)
> **Source draft:** `docs/drafts/sbom-pipeline-service-v2/`
> **Created:** 2026-06-12 (Sprint 2 closeout)
> **Due:** Sprint 3 mid (2026-06-22)

## Problem

Sprint 2 shipped two parallel implementations of the SBOM pipeline:

1. **v1** — `agents/roles/security/sbom-generator/` (committed, in
   production-equivalent CI)
2. **v2** — `backend/services/sbom-pipeline-service/` (drafted, not
   committed, incomplete)

The v2 implementation is technically superior in several ways:

- FastAPI + Pydantic v2 (vs. the v1 custom Pydantic v1 patterns)
- Click CLI for offline use
- Pluggable event bus (NATS / in-memory)
- A complete test suite (unit, integration, fixtures)
- Production artifacts (Dockerfile, Makefile, .env.example)
- A source-input format using **prefix-strings**
  (`docker:` | `git:` | `fs:` | `lockfile:`) that is simpler to use
  than v1's typed discriminated union
- A `bom-ref` format of `urn:cdx:<sha256(purl)[:16]>` (64-bit
  stable) that round-trips with `purl`
- Cross-service Pydantic/Zod schemas designed to live in
  `@aicc/shared/security`

But v2 is **incomplete**: `src/sbom_pipeline/syft_wrapper.py` is
missing, and the wire-format change introduced in TypeScript
(`{ source: { kind, value } }` → `{ target: "docker:..." }` or
`{ purl: "pkg:..." }`) is not coordinated with v1.

## Goal

Land v2 as the canonical SBOM pipeline service for Sprint 3, with v1
retired.

## Sub-tickets

### S3.1.1 — Add the missing `syft_wrapper.py` module

- **Owner:** SBOMPipelineAgent
- **Effort:** 1 day
- **Files:** `docs/drafts/sbom-pipeline-service-v2/sbom-pipeline-service/src/sbom_pipeline/syft_wrapper.py`
- **Contract source:** `tests/test_syft_wrapper.py`,
  `parsers.py` (imports `from .syft_wrapper import SyftRunner,
  SyftResult`), `cli.py` (uses `SyftRunner`).
- **Acceptance criteria:**
  1. The module exposes `SyftRunner` and `SyftResult` with the
     signatures inferred from the call sites.
  2. `pytest tests/test_syft_wrapper.py` passes.
  3. The module emits the `devsecops_sbom_generation_duration_seconds`
     metric via the S2.7 observability shim.

### S3.1.2 — Wire v2 into the existing observability shim

- **Owner:** SREEngineer
- **Effort:** 0.5 day
- **Files:** `backend/common/observability-py/` (add a v2-specific
  helper if needed)
- **Acceptance criteria:**
  1. v2 emits the same `devsecops_sbom_*` metrics as v1
  2. `devsecops_active_scans{scanner_type="sbom"}` is incremented
     on scan start, decremented on scan end (success or failure)

### S3.1.3 — Update the TypeScript models and route handler

- **Owner:** FullstackEngineer
- **Effort:** 0.5 day
- **Files:**
  - `backend/models/security/sbom.model.ts` — re-apply the v2 wire
    format (`target` / `purl` / `purlToTarget()`)
  - `backend/services/security/src/routes/sbom-pipeline.ts` —
    re-apply the v2 translation at the route boundary
  - `backend/models/security/README.md` — re-document the v2 wire
    format
  - `backend/services/security/README.md` — re-document the v2 wire
    format
- **Acceptance criteria:**
  1. The discriminated union v1 format is fully replaced
  2. `purlToTarget()` is the only function that needs to be exported
     to upstream callers
  3. `purl` is preserved in the request body (the route handler
     strips it before proxying to v2)

### S3.1.4 — Dark-launch comparison (1% traffic for 7 days)

- **Owner:** SREEngineer
- **Effort:** 0.5 day setup + 7 days soak
- **Acceptance criteria:**
  1. Security-service routes 1% of `POST /sbom/generate` traffic to
     v2 in parallel with v1
  2. A daily job compares the CycloneDX 1.5 output byte-for-byte
     (canonical JSON sort)
  3. A daily report shows p50, p95, p99 latency for v1 and v2
  4. Zero byte-level mismatches for 7 consecutive days
  5. v2 p99 latency is within the v1 SLO (≤ 30s for xlarge)

### S3.1.5 — Cut over to v2 and retire v1

- **Owner:** SBOMPipelineAgent
- **Effort:** 0.5 day
- **Acceptance criteria:**
  1. Security-service points at v2 by default
  2. `agents/roles/security/sbom-generator/` is removed from the
     repo
  3. `docker-compose.yml`, k8s manifests, and CI workflows are
     updated
  4. `CHANGELOG.md` records the v1 → v2 cutover
  5. Architecture docs are updated:
     - `docs/architecture/agent-topology.md` — remove SBOM agent
     - `docs/architecture/system-architecture.md` — update service map
     - `docs/architecture/event-bus.md` — point at v2 topic names
     - `docs/observability/slos-security-stack.md` — confirm v2 emits
       the same metrics
  6. The S2.1 retro entry in `CHANGELOG.md` references the v2
     cutover commit SHA

## Definition of done

- [ ] All five sub-tickets complete
- [ ] Dark-launch comparison is green for 7 days
- [ ] v1 is removed from the repo
- [ ] Architecture docs are updated
- [ ] `CHANGELOG.md` has the v1 → v2 entry
- [ ] S2.11 E2E validation report is referenced in the v2 cutover
      commit
- [ ] Sprint 3 retro notes any v2-vs-v1 surprises

## Risks

- **Wire-format cutover risk.** The `target` / `purl` change touches
  the security-service route handler. Mitigation: dark-launch
  comparison (S3.1.4).
- **Missing `syft_wrapper.py` risk.** The v2 service will not start
  without it. Mitigation: S3.1.1 is the first sub-ticket and blocks
  all others.
- **VulnerabilityIntelligenceAgent dependency.** The S2.2 work that
  introduced the v2 design needs to be coordinated. Mitigation:
  VulnerabilityIntelligenceAgent is a co-reviewer on S3.1.

## Related tickets

- **S2.2** (vuln-intel) — completed, may have residual v2 design
  intent
- **S2.5** (security API) — completed, has the v1 wire format
- **S2.10** (GitOps automation) — depends on the security API
  contract; needs awareness of the cutover
- **S2.11** (E2E validation) — currently being run against v1; will
  need to re-run against v2 after S3.1.5

## Owner sign-off

- [ ] **Lead (Architect)** — approve ticket
- [ ] **SBOMPipelineAgent** — accept ownership
- [ ] **VulnerabilityIntelligenceAgent** — co-reviewer
- [ ] **SREEngineer** — confirm S3.1.2 / S3.1.4 ownership
- [ ] **FullstackEngineer** — confirm S3.1.3 ownership
- [ ] **PlatformArchitect** — confirm wire-format cutover is on the
      event-bus contract surface
