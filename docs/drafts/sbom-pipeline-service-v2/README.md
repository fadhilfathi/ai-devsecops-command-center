# SBOM Pipeline Service v2 — Sprint 3 Refactor Target

> **Status:** DRAFT — DO NOT DEPLOY
> **Source decision:** Sprint 2 closeout review (2026-06-12)
> **Owner (proposed Sprint 3):** SBOMPipelineAgent
> **Reviewer:** Lead (Architect)
> **Estimated effort:** 3–5 days

## Context

During Sprint 2 closeout, the VulnerabilityIntelligenceAgent produced a
second, more complete implementation of the SBOM pipeline service at
`backend/services/sbom-pipeline-service/` in addition to the v1
implementation at `agents/roles/security/sbom-generator/`.

The v2 implementation includes:

- A FastAPI service (Pydantic v2, Click CLI, OTel, aiosqlite)
- Pluggable event bus (NATS / in-memory)
- A full test suite (unit, integration, fixtures)
- Production artifacts: Dockerfile, .dockerignore, .env.example, Makefile
- A complete HTTP API: `/sbom/generate`, `/sbom/analyze`, `/sbom/{id}`,
  `/sbom`, `/healthz`, `/readyz`, `/metrics`
- A source-input format using **prefix-strings**
  (`docker:` | `git:` | `fs:` | `lockfile:`)
- A `bom-ref` format of `urn:cdx:<sha256(purl)[:16]>` (64-bit stable)
- Cross-service Pydantic/Zod schemas designed for the
  `agents/roles/security/sbom-generator/` family
- A `CHANGELOG.md` and `README.md` that document it as the canonical
  replacement for v1

## Why parked, not promoted

The v2 implementation has a structural problem: it is **missing
`src/sbom_pipeline/syft_wrapper.py`**, the module that wraps the Syft
CLI. The API, parsers, store, and bus all import from it:

```python
# src/sbom_pipeline/api.py:11
from sbom_pipeline.syft_wrapper import SyftResult, SyftRunner
```

Without this module, the service **will not start**. The
`test_syft_wrapper.py` test file exists and is well-structured, so the
intended contract is clear, but the implementation is missing.

The v2 also introduced a **wire-format change**
(`{ source: { kind, value, ... } }` → `{ target: "docker:..." }` or
`{ purl: "pkg:..." }`) that breaks compatibility with the v1
implementation currently in production. Adopting v2 therefore requires a
coordinated TypeScript + Python cutover.

## Decision

Sprint 2 closes with the **v1 implementation at
`agents/roles/security/sbom-generator/` as the canonical
implementation**. The v2 work is preserved here as a Sprint 3 refactor
target.

Justification:

- v1 is complete, tested, and has all production artifacts
  (Dockerfile, k8s manifests, CI, examples, fixtures, scripts)
- v1 is the S2.1 deliverable that was reviewed and committed in
  commits 33eb653 and 5ae2dc1
- v2 is incomplete (missing `syft_wrapper.py`) and would require a
  coordinated TypeScript + Python cutover to deploy
- v2 was not ratified as the S2.1 canonical before closeout
- The wire-format change introduces a migration risk that is better
  owned by a single Sprint than a fast-follow

The v2 design is technically sound and represents the right end-state
for the SBOM pipeline. The Sprint 3 work below is to land it without
disrupting production.

## Sprint 3 deliverables

The Sprint 3 ticket (see `docs/sprint-3/sbom-pipeline-v2-cutover.md`)
will:

1. **Complete the v2 implementation**
   - Add `src/sbom_pipeline/syft_wrapper.py` (contract defined by
     `tests/test_syft_wrapper.py` and `parsers.py` imports)
   - Run the test suite to green
   - Add integration tests against a live Syft binary
   - Add OTel exporter wiring for the new SLO metric set

2. **Coordinate the TypeScript cutover**
   - Update `backend/models/security/sbom.model.ts` to the v2 wire
     format (`target` / `purl` / `purlToTarget()`) — the model is
     already drafted, just needs to be re-applied
   - Update `backend/services/security/src/routes/sbom-pipeline.ts`
     to translate `purl` → `target` at the boundary
   - Update `backend/models/security/README.md` and
     `backend/services/security/README.md` to document the v2 wire
     format

3. **Run a dark-launch comparison**
   - Deploy v2 side-by-side with v1 in the same cluster
   - Mirror 1% of `POST /sbom/generate` traffic to v2
   - Compare CycloneDX 1.5 output byte-for-byte (canonical JSON sort)
   - Compare p99 latency against the v1 SLOs

4. **Cut over and retire v1**
   - Switch the security-service to v2
   - Remove `agents/roles/security/sbom-generator/` from the repo
   - Update `docker-compose.yml`, k8s manifests, CI workflows
   - Update the S2.1 retro entry in `CHANGELOG.md`

5. **Update the architecture docs**
   - `docs/architecture/agent-topology.md` — remove SBOM agent
   - `docs/architecture/system-architecture.md` — update service map
   - `docs/architecture/event-bus.md` — point at v2 topic names
   - `docs/observability/slos-security-stack.md` — confirm v2 emits
     the same `devsecops_sbom_*` metrics

## File inventory

```
docs/drafts/sbom-pipeline-service-v2/sbom-pipeline-service/
├── .dockerignore
├── .env.example
├── .gitignore
├── CHANGELOG.md
├── Dockerfile
├── Makefile
├── README.md
├── pyproject.toml
├── src/sbom_pipeline/
│   ├── __init__.py
│   ├── __main__.py
│   ├── analyzer.py
│   ├── api.py
│   ├── bus.py
│   ├── cli.py
│   ├── config.py
│   ├── errors.py
│   ├── main.py
│   ├── models.py
│   ├── parsers.py
│   ├── store.py
│   └── telemetry.py        # ← MISSING: syft_wrapper.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── fixtures/
    │   ├── sample-cyclonedx.json
    │   ├── sample-spdx.spdx
    │   └── sample-syft.json
    ├── test_analyzer.py
    ├── test_api.py
    ├── test_parsers.py
    └── test_syft_wrapper.py
```

## What was reverted for Sprint 2 closeout

The following changes were **not committed** and are now reverted in
the working tree:

- `backend/models/security/sbom.model.ts` — reverted to v1 typed
  discriminated union (`source: { kind, ... }`)
- `backend/services/security/src/routes/sbom-pipeline.ts` — reverted
  to v1 wire format
- `backend/models/security/README.md` — v2 prefix-string spec
  removed
- `backend/services/security/README.md` — v2 prefix-string spec
  removed

The following changes **were committed** as part of Sprint 2
closeout:

- All S2.2 vuln-intel hardening (NVD 2.0, CPE 6-part, OSV score,
  GHSA range, base.py import fix, app.py metrics/logging)
- SLO doc amendments B1–B4 + C1–C3 (per-bucket 99p, steady-state
  targets, `full` algorithm callout, sign-off checkboxes)

## Owner sign-off

- [ ] **Lead (Architect)** — approve Sprint 3 ticket
- [ ] **SBOMPipelineAgent** — accept Sprint 3 ownership
- [ ] **VulnerabilityIntelligenceAgent** — re-affirm v2 intent
- [ ] **SREEngineer** — confirm metric compatibility
- [ ] **PlatformArchitect** — confirm wire-format cutover is on the
  event-bus contract surface
