# Sprint 10 — Agent debt, SBOM analytics performance, dependency review

Sprint 10 picked up the two placeholders and one performance debt flagged
at the end of Sprint 9, applied the 14 open Dependabot updates by hand, and
swept the `ponytail:` markers left across the codebase for real risks.

## RemediationAgent: real dependency-bump proposals (S10-1)

`RemediationAgent` (`backend/services/agent/src/agents/remediation.ts`) ran
a Sprint-1 placeholder — a hard-coded "Bump vulnerable dependency" proposal
with no real patch, for every finding. It now groups findings by package and
proposes the lowest fixed version _at or above the installed version_ that
resolves every finding for that package, deterministically and with no
network call or LLM:

- version comparison is semver for npm/cargo/go/maven/nuget, a small
  PEP440-ish comparator for pypi;
- a fixed version below the currently installed one is a backport for
  another release line, not a resolution of the finding on the installed
  line — it's filtered out (`compareVersions(v, current) >= 0`) instead of
  being read as "already fixed";
- the bump is classified `patch`/`minor`/`major` with a matching risk level,
  and a per-ecosystem `manifestHint` command (`npm install`, `pip install`,
  `go get`, `cargo update`, `dotnet add package`, or a `pom.xml` line) is
  attached — but only when the package name and version match a strict
  per-ecosystem safe-character pattern (`isSafeForHint`); anything else
  (the string is meant to be copied into a shell) gets a "manual update
  required" message instead of an injectable command;
- an unparseable installed version falls back to a `manual_review`
  proposal; a package with no fixed version at or above the installed one
  goes to `unresolved`.

`remediation.apply` (`applyRemediation()`) is explicitly not implemented —
it returns `{ applied: false, message: '...' }`. The agent only produces
suggestions; it never opens a PR or touches a repo.

## SBOM component index at ingest (S10-2)

security-service's SBOM analytics (`services/security-analytics.ts`)
re-parsed every CycloneDX document a tenant owned on every call to
`/v1/sbom/components`, `/security/risk-heatmap`, and `/security/graph` —
fine at demo scale, linear-degrading with SBOM count and document size.
Components and dependency edges are now extracted once at ingest time
(`POST /v1/sboms`, and the demo seed) into a normalised in-memory index on
`SbomRepository` (`replaceComponents`/`listComponents`/`listEdges`).

Findings are still joined against the index at read time — they change
independently of the SBOM document, so caching that join would go stale.
Only the SBOM-document parse (components + edges) is precomputed.
`security-analytics.test.ts` has an `S10-2 component index equality` test
asserting the new index-backed path produces byte-identical output to the
old parse-per-request path for the same fixture. security-service has no
Postgres SBOM repository yet, so the index is in-memory only — lost on
restart, rebuilt on the next ingest.

## Dependabot catch-up (S10-3)

14 open Dependabot PRs from Sprint 9 (grouped Python bumps for the 3
agents, plus GitHub Actions) were applied by hand instead of merged — a bot
merge would put a non-`fadhilfathi` commit on `main`, which the release
workflow rule forbids. Actions bumped and re-pinned to SHA:
`docker/build-push-action` v7.4.0, `actions/labeler` v7.0.0,
`pnpm/action-setup` v6.1.0, `ossf/scorecard-action` v2.4.4,
`github/codeql-action` v4.38.2 (every occurrence, including
`scorecard.yml`'s `upload-sarif`). Python prod/dev deps bumped for
sbom-generator, vuln-intel, dependency-intel (fastapi, pydantic, httpx,
structlog, pytest, mypy, ruff and related); fixed one vuln-intel test that
relied on Starlette's old always-truthy `State.__bool__` (Starlette now
defines `__len__`, so an empty state is falsy). All 14 PRs are now
superseded and can be closed.

## `ponytail:` debt sweep (S10-4)

A repo-wide sweep of the `ponytail:` markers (13 occurrences across 12
files at the start of the sprint) found two that were real reliability
risks and fixed both:

- `kubernetes-service`'s `LiveProvider` per-cluster client cache
  (`clientsFor`) could keep serving a deleted cluster's client indefinitely,
  and never picked up a rotated token/CA bundle until process restart. It
  now re-checks the cluster repository on every use — a cache entry is only
  reused when the cluster still exists for the tenant _and_ a connection
  fingerprint (hash of server/token/caBundle/insecureSkipVerify) matches the
  cached one; otherwise it rebuilds the client. Capped at 256 entries
  (insertion-order LRU) so a churny fleet can't grow the cache unbounded.
  See [ADR 0009](../../adr/0009-live-kubernetes-provider.md).
- `@aicc/shared`'s Redis Streams `EventBus` never reclaimed entries left
  pending by a crashed or failed consumer — they'd sit in the stream's PEL
  forever. The read loop now runs `XAUTOCLAIM` on an interval
  (`reclaimIntervalMs`, default 30s) for entries idle at least `minIdleMs`
  (default 60s) and re-delivers them through the same handler/ack path; once
  an entry's `XPENDING` delivery count exceeds `maxDeliveries` (default 5)
  it's moved to a dead-letter stream (`aicc:events:dlq:<type>`, envelope +
  error metadata) and the original is acked so it stops retrying forever.
  See [ADR 0014](../../adr/0014-redis-streams-event-bus.md).

The other 9 occurrences are accepted simplifications, each already carrying
a named ceiling and an upgrade trigger in its own `ponytail:` comment — see
"Known simplifications" in `ROADMAP.md`'s Sprint 10 section for the full
list (topology/cost-intelligence HMAC token minting per call, topology's
unmodelled `ipBlock` peers, SBOM fixtures without a dependency graph,
fire-and-forget event-bus publishes in k8s-health/runtime-security, the
migration splitter's literal-`;` split, `SbomComponentSchema`'s `any` typing
for the pedigree cycle, and `Service.hasReadyEndpoints` always `false`).

## How to run it

Unchanged from Sprint 9:

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

Unchanged from Sprint 7/8/9 — none has been applied yet:

- Apply the branch protection checklist in
  [`docs/operations/branch-protection.md`](../../operations/branch-protection.md)
  under Settings → Branches.
- Enable GitHub's private vulnerability reporting (Settings →
  Security → Reporting).

## Still deferred

- PyJWT 2.15 PRs (#69/#70) — not part of this sprint's Dependabot batch,
  still open.
- `remediation.apply` — proposals only; no PR/issue-opening integration.
- A cluster-delete route in `kubernetes-service` — there's no CRUD delete
  today, so `LiveProvider`'s S10-4 cache-eviction check (a deleted cluster
  is never served from cache) has nothing to actually trigger it yet
  outside a direct repository/database delete.
- The maintainer manual steps above (branch protection, private
  vulnerability reporting).

## Next steps (Sprint 11)

See `ROADMAP.md`.
