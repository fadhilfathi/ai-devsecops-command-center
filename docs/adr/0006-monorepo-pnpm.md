---
status: accepted
date: 2026-06-12
deciders: GitOpsManager
---

# 0006 — Monorepo with pnpm workspaces

## Context

The system has multiple deployable units (six backend services, one
frontend, an agent runtime, shared libraries) that share types, contracts,
and conventions. We need a single repository, or a federation, that lets us
evolve them together.

## Decision

We use a **monorepo** managed by **pnpm workspaces**.

- Top-level `package.json` declares the workspaces.
- Top-level `pnpm-workspace.yaml` enumerates them.
- Shared code lives in `backend/packages/` (libraries) and
  `backend/common/` (cross-cutting modules), and is depended on by
  services via `"@aicc/shared": "workspace:*"` (and similar).
- A single root `tsconfig.base.json` is the source of truth for compiler
  options; each workspace extends it.
- A single root CI runs `pnpm -r <command>` to fan out lint, test, build.

## Consequences

- **Easier**: atomic refactors across services; one PR can update a
  contract and all consumers; one CI config.
- **Harder**: a single failing service blocks `main`; build graphs can
  become opaque; tooling that assumes single-package repos (e.g. some
  cloud-build UIs) needs additional config.

## Alternatives considered

- **Polyrepo**: rejected. Cross-service changes would require multiple
  PRs and a release coordination dance. Versioning of shared types
  becomes painful.
- **Nx / Turborepo**: considered, deferred. pnpm workspaces + a Makefile
  is enough for Sprint 1. We can layer Nx in later if/when the build
  graph becomes a bottleneck.
- **Bun workspaces**: considered, deferred. Bun is fast but our runtime
  is Node; mixing is more friction than value today.
