# CLAUDE.md — AI-DevSecOps Command Center (AICC)

Monorepo: pnpm workspaces. Fastify/TypeScript backend services, Vite/React frontend, Python security agents.
Status: pre-alpha, Sprint 5 of 12. See `ROADMAP.md`, `CHANGELOG.md`, `docs/architecture/`.

## Hard rules

- **Commits**: author is the repo's git identity (`fadhilfathi`). Never add `Co-Authored-By`, never mention Claude, AI, or any model in commit messages, PR bodies, comments, or contributor lists. Conventional Commits: `type(scope): subject`.
- **Zero cost**: no paid APIs, no cloud accounts, no SaaS trials. Everything runs locally (docker-compose, SQLite/Postgres in Docker, mocked providers) or on free GitHub Actions. LLM features must have a no-key fallback (heuristic / stub).
- **Model split**: Opus 5 (main session) plans, orchestrates, reviews plans, does small edits. Heavy work — implementing, fixing, coding, reviewing diffs — goes to the Sonnet 5 subagents in `.claude/agents/` (`executor`, `reviewer`). Every executor task gets a `reviewer` pass before commit.
- **Delete over add**. No speculative abstractions, no placeholder dirs/READMEs, no `.gitkeep`. YAGNI.
- **Workflow**: work in phases (one sprint ticket or coherent step = one phase). At the end of every phase: run `reviewer`, fix blockers, commit, `git push origin main`, then pause and report to the user in a few lines (what shipped, what's next, any question). Do not start the next phase until the user says go.
- **Communication**: terse. Questions and reports as short as possible. Ask only when a decision materially changes the work; otherwise pick the recommended option and state it.
- Don't run anything from `main` in production. Don't commit secrets; `.env.example` only.

## Layout

```
backend/services/<name>/   Fastify service, src/index.ts, tsx dev, tsc build (13 services)
backend/packages/shared/   Shared types, contracts, events
backend/common/            observability (TS), observability-py (Python reference)
backend/models/            Zod schemas
frontend/                  Vite + React + Tailwind. src/routes = pages, src/lib/api.ts = all fetches
agents/roles/security/     Python agents: sbom-generator, vuln-intel, dependency-intel (pyproject, pytest)
infra/                     docker-compose, prometheus/grafana/loki/otel configs
security/wire-format/      JSON schemas for cross-service payloads; tests/contracts validates them
docs/                      adr/, architecture/, compliance/, observability/, runbooks/
scripts/                   smoke_*.py, verify_compile.py
```

Ports: auth 3001, agent 3002, security 3003, incident 3004, compliance 3005, integration 3006, kubernetes 4006, k8s-health 4007, runtime-security 4008, inventory 4009, cost-intelligence 4010, topology 4011, reporting 4012.

## Commands

```
corepack enable && pnpm install        # pnpm not installed globally; corepack ships with Node
pnpm -r build                          # tsc all workspaces
pnpm -r --if-present lint
pnpm --filter <pkg> dev                # e.g. @aicc/security-service
cd frontend && pnpm typecheck && pnpm build
cd agents/roles/security/<agent> && pip install -e .[dev] && pytest
python scripts/verify_compile.py
make up / make down                    # docker-compose stack
```

Known gaps (as of 2026-09-21): no `node_modules` has ever been installed here; every backend service has `"test": "echo ..."` — no TS tests exist yet. Verify `pnpm -r build` passes before trusting any change.

## Conventions

- TypeScript strict, ESM, Fastify plugins per route file under `src/routes/`, repositories under `src/repositories/`, providers (external systems) under `src/providers/` with an in-memory mock.
- Frontend: no `fetch` in components — go through `src/lib/api.ts`; mock data lives in `src/lib/*.mock.ts`.
- Python: `src/<pkg>/` layout, pydantic models, pytest in `tests/`.
- New ADR for any architectural decision: `docs/adr/NNNN-title.md`.
- Update `CHANGELOG.md` (Unreleased section) in the same commit as the feature.
