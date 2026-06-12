---
name: Sprint 2 coordination — backend package split
description: FullstackEngineer and GitOpsManager commitments for the Sprint 2 backend package split + port renumber + Turborepo migration
type: project
---

# Sprint 2 coordination — backend package split

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

- **Lead confirmation** that this is the Sprint 2 plan (and not a
  different reshaping).
- **Loki config** for docker-compose (SRE follow-up from Sprint 1).
- **Runbook URL templating** in `infra/observability/prometheus/alert-rules.yml`
  (SRE follow-up from Sprint 1).
- One stale path in `memory/monitoring-architecture.md` referencing the
  old root-level `infra/observability/alertmanager.yml` (SRE follow-up
  from Sprint 1).
