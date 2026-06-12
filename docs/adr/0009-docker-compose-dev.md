---
status: proposed
date: 2026-06-12
deciders: GitOpsManager, SREEngineer
---

# 0009 — Local development via Docker Compose

## Context

Every developer needs a self-contained way to run the entire stack
on their laptop. We have six backend services, a frontend, three
datastores, and an observability stack.

## Decision (proposed)

- `docker-compose.yml` at the repo root brings up the full stack with
  one command (`make up`).
- Each service has a `Dockerfile` and is built from the monorepo root
  context.
- The frontend uses a dev-mode Vite container with hot-reload.
- A `.env` file (git-ignored) provides secrets; defaults are baked in
  for non-sensitive values.
- A `Makefile` exposes the most common commands (`up`, `down`, `logs`,
  `test`, `db-migrate`, `db-reset`).

## Consequences

- **Easier**: zero-to-running in <10 minutes; no "works on my machine";
  CI uses the same compose file for integration tests.
- **Harder**: Docker Desktop licensing on some platforms; resource
  pressure on smaller laptops; some Linux host kernel features
  (e.g. inotify limits) need tuning.

## Alternatives considered

- **Native Node.js for everything, only Postgres + Redis in containers**:
  considered for v1. Lower resource use but every developer has to
  install Node, Postgres client, Redis client, OTel collector, etc.
  Compose is a better default.
- **Devcontainers**: defer. Worth layering on top of compose later, not
  instead of it.
