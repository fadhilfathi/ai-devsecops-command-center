---
name: Sprint 2 coordination — backend package split
description: FullstackEngineer and GitOpsManager commitments for the Sprint 2 backend package split + port renumber + Turborepo migration
type: project
status: LOCKED
---

# Sprint 2 coordination — backend package split

> **Status: LOCKED 2026-06-12.** Three-party contract (Lead /
> FullstackEngineer as Driver / GitOpsManager as Reviewer), pnpm +
> Turborepo ratified, file scope clean, trigger signal defined.
> Do not edit this memo's "Contract clarifications" section without
> Lead approval; additions to "Open items" are fine.
>
> Date: 2026-06-12
> Owners: FullstackEngineer (code), GitOpsManager (docs/tooling)
> Trigger: Sprint 2 kickoff (awaiting Lead)

## Context

At the end of Sprint 1, the team decided to defer the **9-step spec**
(6 separate shared packages, Prisma + Redis Streams, Turborepo, RS256,
ports 3001-3006) from Sprint 1 into Sprint 2. The Sprint 1 tree
(currently on disk) keeps the simpler layout:

- `backend/packages/shared/` containing `@aicc/shared`
- `backend/services/<name>/` containing `@aicc/<name>-service`
- `backend/common/observability/` (TS reference impl)
- `pnpm` workspaces (not Turborepo)
- Ports 3001-3006

The 9-step spec calls for:

1. **Six shared packages** (not one): `@aicc/shared-types`,
   `@aicc/event-bus`, `@aicc/auth`, `@aicc/db`, `@aicc/logger`,
   `@aicc/metrics` under `backend/packages/`.
2. **Prisma** as the data-access layer; Redis Streams as the bus.
3. **Turborepo** (not pnpm workspaces alone) for the build graph.
4. **RS256** JWT signing (asymmetric, not HS256).
5. **Port renumber** 4001-4006 → 3001-3006 in the new spec. (Sprint 1
   already uses 3001-3006 on disk, so this is a no-op for the port
   aspect; the spec is the source of truth for 3001-3006 going forward.)

## FullstackEngineer commitments (Sprint 2)

1. Use the existing `@aicc/shared` as the migration source and split it
   into the six target packages along the boundaries the spec implies.
2. Port renumber (no-op, already 3001-3006 on disk) and
   workspaces→Turborepo migration as a **single PR** so the build graph
   moves atomically.
3. **Hold README/CHANGELOG/PROJECT_DESCRIPTION updates until after the
   code lands**, so docs reference the real on-disk layout.

## GitOpsManager commitments (Sprint 2)

When FullstackEngineer signals the code PR is ready, do a single docs PR
that:

1. Rewrites relevant sections of `README.md`, `CHANGELOG.md`,
   `PROJECT_DESCRIPTION.md`, `backend/README.md`, service READMEs,
   `Makefile` per-service targets, architecture doc cross-references, and
   ADR cross-refs.
2. Adds an ADR for the workspaces→Turborepo decision (or supersedes 0006
   if FullstackEngineer wants the existing one replaced) — their call.
3. Updates `memory/project-conventions.md` and `memory/MEMORY.md` to
   reflect the new layout.
4. Updates the root `package.json` workspaces and `pnpm-workspace.yaml`
   to match the new package set, and migrates the Makefile's
   `--filter @aicc/...` patterns.
5. Does the migration in one commit chain so the diff is reviewable as
   a unit.

## Constraints GitOpsManager will respect

- Will not touch any file outside `*.md`, `Makefile`, `package.json`,
  `pnpm-workspace.yaml`, `tsconfig.base.json`, `.env.example`,
  `docker-compose.yml` (if the service rename touches it), `memory/`,
  and ADR files. The code is FullstackEngineer's.
- Will not start until FullstackEngineer says the code PR is merged (or,
  at minimum, that the on-disk layout is final).
- Will not re-shape the architecture docs (PlatformArchitect's canonical
  work) — only update cross-references that depend on package names or
  ports.

## Contract clarifications (post-Sprint-1-handoff, 2026-06-12)

### "Code PR is ready" signal

FullstackEngineer will post in the team channel with:
- the PR link
- a summary of what changed

That's the signal. GitOpsManager does not need to be pinged directly.

Docs PR will land within 24h of the signal, gated on:
- PR is merged to `main` (preferred), OR
- the on-disk layout is final and confirmed in the channel.

### ADR preference

**New ADR (e.g. 0008) > supersede 0006.**

Cleaner audit trail. 0006 stays as the historical "we chose pnpm
workspaces" decision (Sprint 1). The new ADR references 0006 explicitly
in its Context section and explains the evolution. Status: `accepted`.

GitOpsManager owns writing the new ADR in the docs PR.

### Package manager (pnpm vs npm)

**RESOLVED 2026-06-12 (Leader decision).** See
[`decision-pnpm-turborepo.md`](./decision-pnpm-turborepo.md).

**Stay on pnpm + add Turborepo. No npm migration.**

Reasons (Leader):
- Sprint 1 is already on pnpm; switching to npm is gratuitous churn.
- pnpm + Turborepo is the well-supported 2026 default.
- pnpm is faster, more disk-efficient, and avoids known npm + Turborepo
  cache quirks.
- One package manager is the right call; multi-PM support is punted
  to Sprint 3+ if ever.

Implications (per Leader):
- FullstackEngineer splits `@aicc/shared` into 6 target packages using
  pnpm workspaces.
- Turborepo is added at the repo root (`turbo.json`) for
  build/test/lint pipeline.
- CI workflows pin pnpm, not npm.
- `Makefile` keeps pnpm everywhere.
- `pnpm-lock.yaml` is the source of truth; no `package-lock.json`.

GitOpsManager is the **Reviewer** of this decision per the Leader's
note in `decision-pnpm-turborepo.md`. GitOpsManager's docs PR is
unchanged: all pnpm references in `Makefile`, `package.json`,
`pnpm-workspace.yaml`, `.env.example`, and `*.md` stand.

### File scope

Confirmed. The docs-side file list maps 1:1 with no code overlap:
- `*.md`
- `Makefile`
- `package.json`
- `pnpm-workspace.yaml` (or `package.json` `workspaces` if npm)
- `tsconfig.base.json`
- `.env.example`
- `docker-compose.yml` (if service rename touches it)
- `memory/`
- ADR files

## Decision rationale

The team agreed **option (a)**: keep the on-disk Sprint 1 layout and
carry the 9-step reshape into Sprint 2 with a single atomic code PR + a
single docs PR after. This:

- Preserves the clean Sprint 1 commit log (the Lead already signed off).
- Avoids retroactive churn on docs.
- Keeps the build graph moving as a single atomic unit (Turborepo +
  package split + port renumber) so reviewers can validate the graph
  end-to-end.
- Lets the docs PR be a "we followed the code" PR, which is much
  easier to review than a docs PR that re-implements the spec in
  markdown.

## Open items at time of writing

- **Lead confirmation** of Sprint 2 plan — implicit, awaiting the
  formal kickoff message.
- **Runbook URL templating** in `infra/observability/prometheus/alert-rules.yml`
  (SRE follow-up from Sprint 1).
- One stale path in `memory/monitoring-architecture.md` referencing the
  old root-level `infra/observability/alertmanager.yml` (SRE follow-up
  from Sprint 1).
- **Loki config** — ✅ resolved 2026-06-12 (SREEngineer published
  `infra/observability/loki-config.yaml`; GitOpsManager uncommented
  the docker-compose mount).
