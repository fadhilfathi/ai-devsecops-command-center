# Sprint 9 — Test debt, export UX, bundle size, agent triage

Sprint 9 closed out debt from Sprint 8's release push: 11 pre-existing
failing Python tests that were hiding real SSRF bugs, the SBOM page's
export button (still mock-only), a single 242 KB gz frontend bundle,
and the triage agent's Sprint-1 placeholder.

## sbom-generator SSRF fixes and CI gating (S9-1)

The 11 failing `sbom-generator` tests carried over from Sprint 8 (and,
per their symptoms, present since Sprint 2) weren't just flaky —
`test_ssrf.py` was failing because it mocked a module-level
`asyncio.getaddrinfo` that doesn't exist, which meant the real SSRF
guard was never exercised by the test suite at all. Fixing the mock
(patch the event loop instead) surfaced two real bugs it had been
hiding:

- `extract_host` didn't strip the `user@` prefix from scp-style git
  URLs (`git@10.0.0.1:org/repo.git`), so a private-IP host could slip
  past the SSRF blocklist unclassified.
- the SSRF-blocked/error telemetry path called `.value` on a plain
  `str`, turning a should-be-4xx block into a 500.

The git-host allowlist was also being applied to plain
docker/oci/registry image pulls, which meant ordinary image scans with
no explicit registry host default-denied — narrowed to
git-repository sources only, with a bare-image-ref fast path. The
live-`syft` integration tests were skipping non-cleanly (a duplicate
`pytestmark` silently dropped the skip); fixed so they skip when
`syft` isn't on `$PATH` instead of failing.

`.github/workflows/ci.yml` gained a `test-python` job (matrix over
sbom-generator, vuln-intel, dependency-intel) — the three Python
agents have shipped inside the compose stack since S8-5 but were
never run in CI.

## Real SBOM export download (S9-2)

`sbomExportUrl()` — mock-only since S8-4, because the SBOM page had
no async fetch-then-download flow — is replaced by
`api.downloadSbom()`: an async fetch against security-service's
`GET /v1/sboms/:id/export` (added in S8-4), streamed to a `Blob` and
downloaded via `URL.createObjectURL`, named from the response's
sanitised `Content-Disposition` filename (path-traversal/control-char
safe, capped length). A 501 (stored format differs from the requested
one) surfaces as an inline "stored in another format" message. In
live mode (mocks off), every other export failure now throws a typed
`SbomExportError` shown inline and marks the API degraded — it no
longer silently substitutes the mock SBOM for a real export failure.

## Route-level code splitting (S9-3)

Every page route in `frontend/src/App.tsx` is now `React.lazy` behind
one `<Suspense>` boundary, dropping the main JS chunk from ~242 KB gz
to ~101 KB gz — `recharts` (`CartesianChart`, ~87 KB gz) and
`reactflow` (`Graph`, ~46 KB gz) now ship only on the pages that use
them. A new `RouteErrorBoundary` wraps the lazy route tree: a page
crash shows a short message and a "Reload" button instead of a blank
screen, and a stale chunk after a redeploy (`ChunkLoadError` / a
failed dynamic `import()`) gets an "app was updated" message instead
of a generic one. Resets per route.

## Triage agent heuristic + optional LLM (S9-4)

`agent-service`'s `TriageAgent` ran a Sprint-1 placeholder (a severity
count with no rationale). It now runs a deterministic, explainable
heuristic — severity + KEV + EPSS + exposure + asset criticality
scoring, with a human-readable rationale per finding — and the
decision (triage / escalate / suppress) is derived from that priority
instead of being scored independently. An opt-in LLM refinement pass
(`AICC_AGENT_LLM_ENABLED`, an OpenAI-compatible endpoint including a
local Ollama server, same client shape as `vuln-intel`'s) can only
nudge the heuristic's priority by one level, sees only structured
fields (no free-text prompt injection surface), and falls back to the
heuristic on any failure — no paid API required to run the platform.
See [ADR 0020](../../adr/0020-triage-heuristic-and-optional-llm.md).

`RemediationAgent` (`backend/services/agent/src/agents/registry.ts`)
is still the Sprint-1 placeholder — a hard-coded "Bump vulnerable
dependency" proposal with no real patch. Picked up in Sprint 10
(S10-1).

## sbom-generator registry source fix (S9-5)

A follow-up from the S9-1 security review: the `registry` source type
passed `registry:https://host/...` to syft — a double scheme syft
parsed as an image literally named `https`, so `registry` sources
never actually worked, in any sprint. Fixed by converting the
validated `http(s)://host[:port]/repo[:tag]` URL into a plain OCI
image reference and running it through the same
`security/ssrf.py::parse_image_reference` grammar and
allow-list/blocklist/DNS-rebind check as `docker-image`/`oci-image`
sources — one shared path for all three, rejecting userinfo, query
strings, and fragments in the registry URL.

`git-repository` host extraction now goes through the same hardened
`security/ssrf.py::extract_host` parser instead of a bespoke regex
(previously duplicated, now one parser for both call sites), and a
password embedded in a git URL (`https://user:pass@host/...`) is
rejected as a credential leak. A bare `git@host` SSH username is
still allowed. IPv6 registry hosts are deliberately unsupported —
`extract_host` has no bracket-literal handling, so an IPv6 literal
host fails closed rather than bypassing the allow-list.

## How to run it

Unchanged from Sprint 8:

```bash
pnpm install
pnpm --filter @aicc/security-service dev   # etc., per service
cd frontend && pnpm dev                     # mocks on by default
```

or the full containerised stack:

```bash
docker compose up --build
node scripts/e2e-smoke.mjs
```

## Manual steps for the maintainer

Unchanged from Sprint 7/8 — neither has been applied yet:

- Apply the branch protection checklist in
  [`docs/operations/branch-protection.md`](../../operations/branch-protection.md)
  under Settings → Branches.
- Enable GitHub's private vulnerability reporting (Settings →
  Security → Reporting).

## Still deferred

- `RemediationAgent` (`agents/registry.ts`) is still the Sprint-1
  hard-coded placeholder.
- security-service's SBOM analytics (`services/security-analytics.ts`)
  re-parse every SBOM document a tenant owns on every request
  (components, graph, heatmap endpoints) — fine at demo/seed scale,
  degrades linearly with SBOM count and document size. Marked
  `ponytail:` in the code with the upgrade path (precompute at ingest,
  or cap to the latest SBOM per asset).
- 14 Dependabot PRs are open (grouped Python production/dev bumps for
  the 3 agents, plus GitHub Actions bumps) — none reviewed yet.
- Vite is still on 7.x; 8 is out and not evaluated.

## Next steps (Sprint 10)

See `ROADMAP.md`.
