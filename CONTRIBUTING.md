# Contributing to AI-DevSecOps-Command-Center

Thank you for your interest in contributing! :sparkles: This document describes
how we work, what we expect from contributions, and how to get your change
merged smoothly.

## Table of contents

1. [Code of conduct](#code-of-conduct)
2. [Project goals](#project-goals)
3. [Getting started](#getting-started)
4. [Development workflow](#development-workflow)
5. [Coding standards](#coding-standards)
6. [Testing requirements](#testing-requirements)
7. [Pull request process](#pull-request-process)
8. [Release process](#release-process)
9. [Security disclosures](#security-disclosures)
10. [Community](#community)

## Code of conduct

All participants are expected to follow our [Code of Conduct](./CODE_OF_CONDUCT.md).
Be kind, assume good intent, and help others learn.

## Project goals

The AI-DevSecOps Command Center exists to:

- Provide a single pane of glass for **assets, incidents, vulnerabilities,
  SBOM, compliance**, and **integrations**.
- Run a fleet of **specialized AI agents** (security, incident, compliance,
  integration, …) that collaborate over a typed event bus.
- Integrate with developer workflows (GitHub, GitLab, CI systems) so security
  findings show up where work happens.
- Make **audit-ready evidence** a first-class output, not an afterthought.
- Be **multi-tenant** and **deployable on-prem** (no required SaaS calls for
  the core experience).

We optimize for: correctness > operability > developer experience > speed of
ship. A slow, reliable, auditable system is the goal.

## Getting started

### Prerequisites

- **Node.js** `>= 20.18.0` (see `.nvmrc`)
- **pnpm** `>= 9.0.0` (`npm install -g pnpm`)
- **Docker** + **Docker Compose v2** for the local stack
- **git** with a configured user.name and user.email

### First checkout

```bash
git clone https://github.com/aionrs/ai-devsecops-command-center.git
cd ai-devsecops-command-center
pnpm install
cp .env.example .env       # edit secrets, never commit
make up                     # bring up Postgres, Redis, services, frontend
```

Open <http://localhost:5173> for the UI and <http://localhost:3001> for Grafana
(default creds `admin` / `admin`).

## Development workflow

1. **Pick or create an issue.** Anything non-trivial should have an issue
   describing the user problem, the proposed approach, and acceptance criteria.
2. **Branch from `develop`.** Branch name format: `type/issue-id-short-desc`
   - `feat/412-incident-correlation`
   - `fix/189-jwt-refresh-loop`
   - `docs/22-rbac-explainer`
   - `chore/bump-fastify-5`
3. **Work in small, focused commits.** Conventional Commits are required
   (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, …).
4. **Run the test suite locally** before pushing.
5. **Push and open a PR** against `develop`. Use the PR template.
6. **Pass CI and code review.** A PR needs:
   - At least one approving review from a code owner
     (see [`.github/CODEOWNERS`](./.github/CODEOWNERS))
   - All CI checks green
   - No unresolved review comments
7. **Squash-merge** with a Conventional Commit message.

## Coding standards

### Languages

- **TypeScript** everywhere on the backend and the frontend.
- **Strict mode** is non-negotiable. `tsconfig.base.json` enables
  `strict`, `noUncheckedIndexedAccess`, `noImplicitAny`, and friends.
- **ES Modules** (`import` / `export`), NodeNext resolution. No CommonJS
  in application code.

### Style

- **Prettier** owns formatting. Run `pnpm format` or configure your editor.
- **ESLint** owns linting. We extend `@aionrs/eslint-config` and forbid `any`
  except in tightly-scoped escape hatches.
- **Naming**:
  - Files: `kebab-case.ts` (services), `PascalCase.tsx` (React components).
  - Variables / functions: `camelCase`.
  - Types / classes / React components: `PascalCase`.
  - Constants: `SCREAMING_SNAKE_CASE`.
- **Imports**: group `node` → `external` → `internal` → `relative`; lint will
  enforce order.

### TypeScript guidelines

- Prefer **explicit return types** on public functions and exported APIs.
- Prefer **`unknown` + type guards** over `any`.
- Prefer **discriminated unions** to optional fields where possible.
- Avoid **`as` casts** outside of well-typed boundaries (e.g. JSON parsing).
- Use **branded types** for IDs (`type UserId = string & { __brand: 'UserId' }`).

### Backend (Fastify) guidelines

- One **plugin** per resource (`/auth`, `/users`, …), no giant `server.ts`.
- All handlers receive a typed `FastifyRequest<{ Body: …, Params: … }>`.
- All I/O has a timeout, a circuit breaker, and is observed with metrics.
- Use **dependency injection** via Fastify decorators — no module-level
  singletons that hide test seams.

### Frontend (AionUi) guidelines

- **Component-first**: a screen is a composition of components in
  `frontend/src/components/`. No business logic in JSX.
- **Hooks for state**: data fetching, mutations, and event subscriptions all
  live in custom hooks under `frontend/src/hooks/`.
- **No direct `fetch`** in components — go through `frontend/src/services/`.
- **Strict accessibility**: every interactive element is reachable by keyboard
  and has an accessible name.

### Agent guidelines

- An agent is a **typed contract** (`input`, `output`, `events consumed`,
  `events produced`) plus a **runtime adapter** (e.g. AionRs / Claude / local).
- Agent code must be **deterministic given the same inputs and seed** where
  possible; document any non-determinism in the agent README.
- All agent actions that change external state go through an **integration
  adapter** (never call the GitHub API directly from a prompt handler).

## Testing requirements

| Layer        | Tool             | Min coverage (line) |
| ------------ | ---------------- | ------------------- |
| Backend      | Vitest           | 80%                 |
| Frontend     | Vitest + RTL     | 70%                 |
| Agents       | Vitest           | 80%                 |
| E2E          | Playwright       | critical paths      |
| Contracts    | Pact / schemas   | n/a (must be green) |

A PR that **drops** overall coverage by more than 1 percentage point requires
a justification in the PR description.

## Pull request process

See [`.github/PULL_REQUEST_TEMPLATE.md`](./.github/PULL_REQUEST_TEMPLATE.md)
for the template. Highlights:

- Link to an issue (`Closes #123`).
- Describe the **user-visible** change in one paragraph.
- List the **test coverage** you added.
- Flag **breaking changes** explicitly.
- Update [`CHANGELOG.md`](./CHANGELOG.md) under `## [Unreleased]`.
- Update docs (`docs/`, `README.md`) if behavior changed.

PRs without a linked issue and a clear "what changed" section may be closed
with a polite request for more context.

## Release process

- Releases are cut from `main` via the
  [`release`](./.github/workflows/release.yml) workflow.
- `standard-version` updates `CHANGELOG.md`, bumps versions, tags, and
  publishes a GitHub release.
- SemVer is strict: breaking changes bump the major, features bump the minor,
  fixes bump the patch.

## Security disclosures

Please **do not** file public issues for security vulnerabilities. Follow
[`SECURITY.md`](./SECURITY.md).

## Community

- GitHub Discussions: general questions, RFCs, "how do I…"
- GitHub Issues: bug reports, feature requests
- Chat: (TBD — see `README.md` for current link)
- Office hours: weekly, posted in Discussions

We are friendly to first-time contributors. Look for issues tagged
`good first issue` and `help wanted`.
