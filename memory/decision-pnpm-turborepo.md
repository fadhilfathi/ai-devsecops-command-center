---
name: pnpm + Turborepo Decision
description: Package manager and monorepo toolchain decision for Sprint 2
type: project
---

# Decision: pnpm + Turborepo for Sprint 2

**Decided by:** Leader
**Date:** 2026-06-12
**Status:** ACTIVE — informs Sprint 2 backend package split

## Decision

Stay on **pnpm** workspaces and add **Turborepo** on top. Do **not** migrate to npm workspaces.

## Rationale

1. **Continuity with Sprint 1.** Sprint 1 is already on pnpm
   (`package.json` declares `"packageManager": "pnpm@9.12.0"`,
   `pnpm-workspace.yaml` enumerates workspaces, `Makefile` uses pnpm,
   lockfile is `pnpm-lock.yaml`).
2. **De-facto 2026 toolchain.** pnpm + Turborepo is the well-supported
   combination widely adopted in 2026.
3. **Performance.** pnpm is materially faster and more disk-efficient
   than npm (matters for CI cache size).
4. **Avoids known npm + Turborepo cache-invalidation quirks.**
5. **Switching to npm would be gratuitous churn** for no functional gain.

## Alternatives Considered

| Option | Verdict |
|---|---|
| **pnpm + Turborepo** (chosen) | Best — continuity + perf + ecosystem |
| npm workspaces + Turborepo | Rejected — gratuitous churn, known quirks |
| pnpm-only (no Turborepo) | Rejected — Turborepo gives us build orchestration we need for the 6-service split |
| Support both | Rejected — punted to Sprint 3, premature abstraction |

## What This Means for Sprint 2

- FullstackEngineer splits `@aicc/shared` into 6 target packages using pnpm workspaces.
- Turborepo is added at the repo root (`turbo.json`) for the build/test/lint pipeline.
- CI workflows pin pnpm, not npm.
- `Makefile` keeps `pnpm` everywhere.
- No `package-lock.json` is committed; `pnpm-lock.yaml` is the source of truth.

## What This Precludes (Sprint 3+)

- npm workspaces support — not on the roadmap.
- Yarn / Bun workspaces — explicitly out of scope.

## Coordination

- **Owner of this decision:** Leader.
- **Implementer:** FullstackEngineer (Sprint 2 backend split).
- **Reviewer:** GitOpsManager (Sprint 2 docs PR).
- **Informed:** all teammates.
