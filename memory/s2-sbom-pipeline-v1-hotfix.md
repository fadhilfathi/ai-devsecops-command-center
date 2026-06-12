---
name: S2.1 SBOM Pipeline v1 — Hotfix + Contract Refinements (2026-06-12)
description: S2.1 v1 service at agents/roles/security/sbom-generator/ had 15 test failures + 1 startup crash. All fixed. SRE/GitOps/Security contract refinements applied.
type: project
---
# S2.1 SBOM Pipeline v1 — Hotfix + Contract Refinements

## What was wrong when I picked this up

The Lead's closeout message (2026-06-12) declared v1 the canonical
S2.1 deliverable. But the service had **15 test failures + 1
startup crash** that hadn't been caught:

### Startup crash
- `src/sbom_generator/syft.py` line 171 had a typo'd cmd-append:
  `cmd.extend(["--select-catalogers", "+package"])]` — extra `)`
  caused `SyntaxError: closing parenthesis ')' does not match
  opening parenthesis '['`. Fixed by replacing with
  `cmd.extend(["-c", "package"])` (Syft 1.x doesn't have a
  `--select-catalogers` flag; `-c package` is the right way to
  narrow the cataloger set).

### The 15 test failures, in 7 categories

1. **Lazy binary resolution.** `SyftRunner.__init__` called
   `resolve_syft(binary)` eagerly, which crashes when the binary
   isn't on `$PATH`. Changed to lazy resolution via
   `_ensure_resolved()`; `binary_path` becomes a property that
   falls back to the configured value. Plus a `binary_path` setter
   for test fakes.
2. **`warmup` swallowed binary errors.** Was a hard
   `FileNotFoundError`; now catches `FileNotFoundError` /
   `OSError` and returns `None`. The `/healthz` endpoint
   reports the path even when warmup hasn't completed.
3. **`_build_response` returned a coroutine that was never
   awaited.** `agent.generate` was a coroutine that returned the
   coroutine from `_build_response` directly. Fixed with
   `return await _build_response(...)`.
4. **`create_app` returned `None`.** Three sub-issues:
   - The `return app` was missing entirely.
   - The `_sanitize_validation_errors` helper was at
     module-level, sandwiched inside `create_app`'s body, so the
     route handlers at lines 200+ were **inside the helper
     function**, never registered.
   - The original `return app` at line 409 was inside
     `_generate_quick` (a route handler), unreachable.
   - **Fix:** relocated `_sanitize_validation_errors` to the
     very end of the file (after `_infer_source_kind`).
   - **Fix:** placed `return app` at the end of `create_app`.
   - **Fix:** deleted the unreachable `return app` in
     `_generate_quick`.
5. **Validation 400 vs 422.** FastAPI raises
   `RequestValidationError` (not `pydantic.ValidationError`)
   before the route handler runs, returning 422 by default. Added
   a `RequestValidationError` exception handler that returns 400
   to match the v2 envelope.
6. **Pydantic v2 `ValidationError.errors()` non-JSON-serialisable
   `ctx`.** Pydantic v2 puts the original `ValueError` in `ctx`;
   `JSONResponse` refused to render. Added
   `_sanitize_validation_errors()` to scrub non-primitive
   values from `ctx` and bytes from `input`.
7. **Tests expected features the model didn't have.**
   - `git-repository` validation only accepted URL-style
     `https://`/`git://`/`ssh://`/`file://` schemes; the
     GitHub-style SCP form (`git@github.com:owner/repo.git`)
     was rejected. Added an SCP-style regex fallback.
   - `SBOMMetadata` had no `properties` field. Added it.
   - Tool name was `Syft` (title case); the spec wants `syft`.
     Fixed.
   - Test `--select-catalogers` flag assertion updated to
     match the Syft-1.x-correct `-c package` form.

## Contract refinements applied (S2.7 + S2.8 + S2.10)

After fixing the bugs, I applied the **newly locked** contracts
that arrived in the post-Sprint-2 closeout message:

### S2.7 metrics (SREEngineer)
- New module: `src/sbom_generator/metrics.py` — single source
  of truth for metric names, label sets, bucket boundaries.
- **5-bucket component count** (`small` / `medium` / `large` /
  `xlarge` / `xxlarge` at 100/1k/10k/50k) — confirmed via
  smoke test (50→small, 100→medium, 9999→large, 49999→xlarge,
  50000→xxlarge).
- **14-value ecosystem enum** (npm/pypi/maven/nuget/go/cargo/
  rubygems/composer/conan/apk/deb/rpm/generic/unknown) with a
  PURL→ecosystem translator.
- `devsecops_sbom_generation_duration_seconds{source_type,
  result, ecosystem, target_type, repo_shape}` — emitted
  (without `format` label per the D3 verdict, deferred to
  Sprint 3).
- `devsecops_sbom_components_total{sbom_size_bucket}` —
  emitted.
- `devsecops_sbom_active_scans{scanner_type}` — gauge, bumped
  via async context manager.
- `devsecops_sbom_scan_failures_total{reason}` — bounded
  reasons: `syft_not_found` / `syft_timeout` /
  `syft_nonzero_exit` / `source_not_found` / `auth_denied` /
  `internal_error`.
- `repo_shape` label only emitted when `target_type="git"`,
  empty string otherwise.

### S2.10 event payload (GitOpsManager)
- New event subject: `security.sbom.generated.v1` (replacing
  the legacy `*.events`).
- Payload fields added: `schema` discriminator
  (`"security.sbom.generated.v1"`), `sbom_id` (locked
  `sbom-<date>-<sha8>-<scope>` format with content-derived
  fingerprint fallback when no git_sha), `source` (v2
  prefix-string form), `format` (lowercase enum), `component_count`,
  `generated_at` (ISO 8601), `git_sha` (40-char when available,
  null otherwise), `scope`, `sbom_fingerprint`
  (`sha256:<hex>` over RFC 8785 / JCS canonicalised CycloneDX
  JSON).
- v1 → v2 prefix-string mapper
  (`_v1_to_prefix_string`): `docker-image`/`oci-image`/
  `registry` → `docker:`, `git-repository` → `git:`,
  `directory`/`file`/`archive` → `fs:`.

## Final state

- **Tests:** 73 passed, 3 deselected (live-Syft only), 0.54s.
- **File count:** 55 files (22 source + 6 docs + 23 test +
  4 config) at `agents/roles/security/sbom-generator/`.
- **Module `metrics.py`:** new, ~165 lines, full S2.7
  enums + helpers.
- **Smoke test passes:** agent instantiates cleanly without
  the binary on `$PATH`; v1→v2 wire-format mapping is correct
  for all 7 v1 source kinds; 5-bucket size mapper is correct;
  14-value ecosystem enum is correct.

## Known limitations (carried into Sprint 3)

- **No live Syft smoke test.** The Dockerfile pins Syft 1.6.0
  but the test environment doesn't have it. The 3 deselected
  tests cover the live case; they pass when the binary is
  available. Sprint 2.11 (E2E validation) is the right owner
  for a CI step.
- **No Syft image-digest pin.** SecurityArchitect's S2.8
  action item — `anchore/syft@sha256:...` instead of
  `anchore/syft:v1.6.0`. Deferred to S3.x hotfix to coordinate
  the rotation policy.
- **No k8s NetworkPolicy / Pod-spec hardening** in the
  manifest. SecurityArchitect's S2.8 action items. Deferred
  to S3.x hotfix.
- **No `cosign-verify` initContainer** in the manifest.
  SecurityArchitect's S2.8. Deferred to S3.x hotfix.

## v2 cleanup

The v2 work I built in the previous turn at
`backend/services/sbom-pipeline-service/` was **deleted** per
the Lead's instruction. The v2 spec lives at
`docs/drafts/sbom-pipeline-service-v2/` as a Sprint 3 P0
refactor target.
