---
name: S2.1 SBOM Pipeline v2 — Missing Module + Test Failures Fixed
description: On 2026-06-12 the v2 spec at backend/services/sbom-pipeline-service/ was missing syft_wrapper.py and had 12 test failures. Both fixed. 69/69 tests pass.
type: project
---
# S2.1 SBOM Pipeline v2 — Module + Test Fixes (2026-06-12)

## What was wrong

When I picked up the S2.1 task mid-session, the v2 service at
`backend/services/sbom-pipeline-service/` had two real problems:

1. **`src/sbom_pipeline/syft_wrapper.py` was missing.** It was
   imported by `api.py`, `cli.py`, `tests/conftest.py`,
   `tests/test_syft_wrapper.py`, and would prevent the service from
   starting. The file is also a non-trivial piece of work
   (~280 lines) — the Syft CLI wrapper, `_syft_target`,
   `_build_command`, `_dominant_ecosystem`, `SyftRunner` class,
   `resolve_syft`, `get_syft_version`, `SUPPORTED_LOCKFILES`.
2. **12 test failures** in the test suite, even with the missing
   module replaced by a stub. They broke down as:
   - `AuthenticationError` / `AuthorizationError` not in
     `errors.py` (import error in `api.py`)
   - `size_bucket` not exported from `analyzer.py` (test_analyzer
     imported it from there, not from telemetry)
   - `aio_sqlite` "you can only execute one statement at a time" —
     the `_INIT_SQL` constant was passed to
     `conn.exec_driver_sql`, which aiosqlite refuses for
     multi-statement strings
   - `Gauge._value.get(...)` private-API call in `api.py` —
     prometheus_client doesn't expose `.get()` on a labeled
     parent's `.labels()` child in a way that works
   - `_parse_size("1.5 mb")` returned `1048576` instead of
     `1572864` — the regex didn't match the decimal point, and
     `int(number) * unit` truncated before multiplying
   - Cycle test: `_transitive_depth({a:[b],b:[a]})` returned `2`
     but the test expected `0`. Cycle → `0` policy.
   - `UNIQUE constraint failed: sboms.id` — `make_id()` was
     deterministic on `(date, git_sha-or-nogit, scope)` and
     produced the same id for 4 different sources with no git_sha
   - Pydantic v2 `ValidationError.errors()` returned dicts with
     a `ValueError` object in `ctx`; `JSONResponse` couldn't
     serialise them. Needed a `_sanitize_validation_errors()`
     helper.

## Fixes applied (all in source at `docs/drafts/sbom-pipeline-service-v2/sbom-pipeline-service/`)

1. **Wrote `syft_wrapper.py`** (281 lines) — full module per the
   `test_syft_wrapper.py` contract: `SUPPORTED_LOCKFILES` (32
   entries: npm/pnpm/yarn/bun/pip/pipenv/poetry/pdm/uv/maven/
   gradle/ivy/cargo/go/composer/ruby-gemfile/dotnet/paket/mix/
   rebar/dart-pub/swift/haskell/conan/vcpkg), `SyftResult`
   dataclass, `SyftRunner` (lazy `binary_path`, `warmup`,
   bounded-concurrency `scan()`), `resolve_syft` ($PATH →
   $SYFT_BINARY → override), `get_syft_version`. Subprocess
   timeout is 600s default — generous for cold-cache docker
   pulls.
2. **Added `AuthenticationError` / `AuthorizationError`** to
   `errors.py` (codes `authentication_error` / 401 and
   `authorization_error` / 403).
3. **Added `size_bucket(n: int) -> str`** to `analyzer.py` with
   the four-bucket boundaries locked with SRE S2.7: <100, <1k,
   <10k, ≥10k → small/medium/large/xlarge. Negative values
   defensively map to "small".
4. **Fixed `_parse_size`** — regex now `(\d+(?:\.\d+)?[\d_]*)`
   and `int(number * _SIZE_UNITS.get(unit, 1))` (multiplies
   before truncating). Handles "1.5 mb", "1_000 kb", "2 GB",
   "1024".
5. **Fixed `_transitive_depth`** — when any cycle is detected
   during DFS, return `0` (longest-path is undefined in a cycle
   graph; the security team wants a bucketable value).
6. **Fixed `store._init_schema`** — use `metadata.create_all`
   for both SQLite and Postgres; keep the hand-written
   `_INIT_SQL` for devs running `sqlite3` by hand.
7. **Added `Telemetry.get_active_scans(scanner_type)`** as a
   public API and replaced the private
   `telemetry.active_scans._value.get(("syft",), 0)` calls in
   `api.py` with it. Returns `0` when no observation yet.
8. **Added `_sanitize_validation_errors()` helper** to `main.py`
   and used it in both Pydantic + FastAPI error handlers.
   Strips the `ValueError` object out of `ctx` and bytes
   out of `input`.
9. **Updated `SBOMRecord.make_id`** to accept a
   `source_fingerprint=` kwarg. The API `generate` handler
   passes `sha256_text(body_text)[:8]` when no `git_sha` is
   given. This keeps IDs unique across multiple scans of
   different sources on the same day (UNIQUE-constraint
   proofing).

## Final state

* **File count:** 33 (8 root config + 14 source + 8 test + 3
  fixture) at `backend/services/sbom-pipeline-service/`
* **Test status:** 69/69 pass, 677 warnings (all from starlette
  using deprecated `asyncio.iscoroutinefunction`, slated for
  removal in Python 3.16 — not our code)
* **Compile:** all 14 source + 5 test files compile clean
* **Test runtime:** 1.25s

## Caveats / known limitations

* The contract between S2.4 (TypeScript Zod schemas) and S2.1
  (Python Pydantic) was not re-validated end-to-end. v2 was
  parked by an earlier Lead decision (see
  `s2-sbom-v2-spec-alignment.md`); the S2.1 task is now
  technically complete at the right location, but the Lead
  should confirm whether v1 at
  `agents/roles/security/sbom-generator/` remains canonical
  or whether v2 should be promoted.
* Tests are run with a `FakeSyft` — the real Syft 1.6.0
  binary in the Dockerfile has not been smoke-tested in this
  environment.
* The `aiosqlite` driver is used in dev; production swap to
  `asyncpg` is wired in `Settings` (`SBOM_DB_URL`) but not
  integration-tested.
