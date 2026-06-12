# ADR 0008: Monorepo tooling — pnpm + Turborepo + `@aicc/shared` sub-path exports

- **Status:** Accepted (Sprint 2, locked by the Lead)
- **Date:** 2026-06-12
- **Deciders:** Lead (final call), FullstackEngineer (Driver), GitOpsManager (Reviewer)
- **Sprint context:** Sprint 2 backend reshape
- **Replaces:** n/a (additive on top of ADR 0006 — monorepo pnpm)

## Context and problem statement

The Sprint 1 monorepo decision (ADR 0006) locked **pnpm workspaces** as
the package manager. Sprint 2 surfaces a second decision point: as the
service count grows (6 → 9 with `sbom-pipeline`, `vuln-intel`,
`dependency-intel`) and the shared code surface grows (security
models, event topics, RBAC middleware, error envelopes), we need
**two orthogonal guarantees** that pnpm-on-its-own does not give us:

1. **Fast, cached, dependency-aware build / lint / test pipelines**
   that run only what changed and reuse cached outputs across services.
2. **Tight, compile-time-enforced ownership** of shared code:
   the security models, event topics, and RBAC middleware must be
   importable from a **single, well-known import path** by every
   service, with the package.json `exports` map preventing
   `../../../packages/shared/src/...` style deep imports that
   couple consumers to file layout.

## Decision drivers

- **Service build speed**: Sprint 1's per-service builds in CI are
  linear in the number of services. Sprint 2 doubles the count, so a
  task-graph-aware orchestrator is needed.
- **Code reuse without coupling**: the security models, event topics,
  and RBAC middleware should be **the** import path for every
  consumer. Drift across services is a known Sprint 1 smell (multiple
  teams hand-rolled slightly different versions of the same Zod
  schema).
- **Ecosystem fit**: the Node.js / TypeScript monorepo tooling
  ecosystem has converged on pnpm + Turborepo. Both are widely
  adopted, well-maintained, and compatible with our pnpm-workspace
  decision.
- **Lockstep release for shared packages**: when `@aicc/shared`
  changes, every service that imports it must be revalidated. A
  task-graph orchestrator does this for free.

## Considered options

### Option A — pnpm workspaces only (status quo of ADR 0006)

- **Pros:** No new tooling; minimal onboarding cost.
- **Cons:** No task graph → linear CI; no cross-service build
  cache; no per-package output hashing; shared code is still
  reachable via deep imports.
- **Verdict:** Rejected — does not address either decision driver.

### Option B — pnpm + Nx

- **Pros:** Mature task graph, remote cache, code generators.
- **Cons:** Heavier than needed for our scale; opinionated
  workspace layout that fights with the pnpm-workspace layout we
  already have; larger learning curve for the team.
- **Verdict:** Rejected — overkill.

### Option C — pnpm + Turborepo ✅

- **Pros:**
  - Drop-in on top of pnpm-workspace (no workspace restructure)
  - Lean: 1 dev dep, ~10 lines of `turbo.json`
  - **Remote cache** out of the box (we will enable Vercel Remote
    Cache in CI; non-blocking for local-only)
  - **Pipeline-aware**: each pipeline task declares its
    `outputs` and `dependsOn`, and Turborepo hashes inputs to
    skip work that did not change
  - Plays well with our `Makefile` (turbo commands are drop-in
    replacements for the per-service targets)
- **Cons:** Smaller ecosystem than Nx; some advanced features
  (e.g. generators) require additional tooling.
- **Verdict:** **Selected.** Best fit for our scale and team
  experience; additive on top of ADR 0006 (no breaking change).

### Option D — npm workspaces (re-evaluate ADR 0006)

- **Verdict:** Rejected — the Lead's Sprint 2 DECISION locked
  pnpm for the project lifecycle. Reopening the package manager
  decision is out of scope for this ADR.

## Decision

We adopt **Option C**: pnpm + Turborepo, with the addition of a
**sub-path export contract** for `@aicc/shared`.

### Sub-path export contract (the new bit)

The `@aicc/shared` package exposes its public surface through
**named sub-paths** declared in `package.json#exports`:

```jsonc
{
  "name": "@aicc/shared",
  "exports": {
    ".":             "./src/index.ts",                 // barrel — security + common + events
    "./security":    "./src/security/index.ts",        // models + topics
    "./security/models": "./src/security/models.ts",   // Zod schemas + types only
    "./security/topics": "./src/security/topics.ts",   // topic constants + event interfaces
    "./events":      "./src/events/index.ts",          // envelope + helper types
    "./rbac":        "./src/rbac/index.ts",            // role constants + check helpers
    "./errors":      "./src/errors/index.ts",          // AppError + RFC 7807 mapper
    "./logger":      "./src/logger/index.ts",          // pino-based structured logger
    "./metrics":     "./src/metrics/index.ts",         // prom-client wrapper + SLO helpers
    "./auth":        "./src/auth/index.ts",            // JWT helpers (HS256 + RS256)
    "./db":          "./src/db/index.ts"               // postgres pool + DAL helpers
  }
}
```

**Hard rules:**

1. **No deep imports.** Importing from
   `@aicc/shared/src/security/topics` (or any path not declared
   in `exports`) is a **build-time error**. ESLint rule
   `no-restricted-imports` enforces this.
2. **Sub-paths are stable across minor versions.** A sub-path
   added in `@aicc/shared@0.2.0` must remain importable through
   the end of the `0.x` line. Renaming a sub-path requires a
   major version bump.
3. **The barrel (`@aicc/shared`) is for cross-cutting code only.**
   Services that only need, e.g., the event topics should
   import from `@aicc/shared/security/topics` to keep the
   bundle small.

### Service-to-sub-path map (Sprint 2 snapshot)

| Service                | Imports from `@aicc/shared`                                       |
| ---------------------- | ----------------------------------------------------------------- |
| `auth-service`         | `./auth`, `./events`, `./logger`, `./errors`                      |
| `agent-service`        | `./auth`, `./events`, `./logger`, `./errors`, `./metrics`         |
| `security-service`     | `./auth`, `./security`, `./security/topics`, `./events`, `./errors`, `./logger`, `./metrics`, `./rbac` |
| `incident-service`     | `./auth`, `./events`, `./errors`, `./logger`                      |
| `compliance-service`   | `./auth`, `./events`, `./errors`, `./logger`, `./rbac`             |
| `integration-service`  | `./auth`, `./events`, `./errors`, `./logger`                      |
| `sbom-pipeline` (4007) | `./security`, `./security/topics`, `./events`, `./logger`         |
| `vuln-intel` (4008)    | `./security`, `./security/topics`, `./events`, `./logger`         |
| `dependency-intel` (4009) | `./security`, `./security/topics`, `./events`, `./logger`      |

### `turbo.json` (top of repo)

```jsonc
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": ["tsconfig.base.json", ".env"],
  "tasks": {
    "build":  { "outputs": ["dist/**"],          "dependsOn": ["^build"] },
    "lint":   { "outputs": [],                    "dependsOn": ["^build"] },
    "test":   { "outputs": ["coverage/**"],       "dependsOn": ["^build"] },
    "typecheck": { "outputs": [],                "dependsOn": ["^build"] },
    "dev":    { "cache": false,                   "persistent": true }
  }
}
```

- `^build` means "depends on the build of every dependency first"
  (Turborepo's topological prefix).
- `dev` is non-cached and persistent (long-running watchers).
- Remote cache: enabled in CI via `TURBO_TOKEN`; local-only in
  developer environments (no token required).

### CI / Makefile integration

The Sprint 1 `Makefile` already has per-service targets
(`dev-auth`, `dev-agent`, …). The Sprint 2 update adds
`make build`, `make lint`, `make test`, `make typecheck` as
**Turbo-powered** drop-in replacements (replacing the per-service
loops). The per-service targets remain for cases where a single
service needs to be developed in isolation.

## Consequences

### Positive

- **CI speed**: Turborepo's remote cache means a 1-service PR
  rebuilds only the affected service in CI (~30s vs ~6min today).
- **Lockstep safety**: a change to `@aicc/shared/security/topics`
  automatically retriggers builds of the 3 services that import
  it (declared in the task graph).
- **No drift**: the sub-path contract is the single source of
  truth; ESLint prevents bypass; no more "the topic is hardcoded
  in 2 different strings" bugs.
- **Onboarding**: `pnpm install && pnpm dev` (or `make dev`)
  brings up the whole stack.

### Negative / risks

- **Turborepo lock-in**: we become tied to its task graph
  semantics. Mitigation: the Makefile wrappers are 5 lines each;
  migrating to Nx later is mechanical.
- **Sub-path surface is now API**: every sub-path is a promise to
  the consumers. Mitigation: sub-paths are added in PRs reviewed
  by the package owner and locked in CHANGELOG.
- **Remote cache cost**: Vercel Remote Cache is free for OSS; for
  a private repo the cost is a few $/mo. Mitigation: the cache
  is opt-in; we can run local-only for the first sprint and turn
  it on when the CI speedup is measured.

## Rollout

1. **Day 1 (this ADR lands):** `turbo.json` + `pnpm-workspace.yaml`
   + `@aicc/shared#exports` map committed; `make build` etc.
   switched to `turbo run`. Per-service `make dev-*` still works.
2. **Day 2:** ESLint `no-restricted-imports` rule added to
   block deep imports.
3. **Day 3+:** Vercel Remote Cache enabled in CI; SLO on PR
   build time tracked in [`docs/observability/`](../observability/).

## Follow-ups (non-blocking)

- **Egress proxy for AI providers**: as the security service
  hits LLM providers directly today, a small in-cluster proxy
  with per-tenant token budgets and redaction would tighten the
  AI safety story. Owner: GitOpsManager + PlatformArchitect.
  Tracked in the "Future refactors" subsection of
  [`./security-model.md`](../architecture/security-model.md#future-refactors-proposed-not-blocking).
- **Per-package versioning**: when `@aicc/shared` reaches 1.0,
  we should consider `changesets` for explicit version bumps
  per sub-path. Out of scope for Sprint 2.
