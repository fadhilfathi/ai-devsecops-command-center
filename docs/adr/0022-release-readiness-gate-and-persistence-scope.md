# 0022 — Release-readiness gate and the boundary of Postgres persistence

Status: accepted
Date: 2026-10-01

## Context

Sprint 12 is the release-readiness sprint, and it had two halves that look
unrelated but share one theme: **turning a stated intention into something the
system actually enforces.**

The first half is the repository's own settings. Since Sprint 7,
`docs/operations/branch-protection.md` had been a checklist for a maintainer
to apply by hand under Settings → Branches, and
[`SECURITY.md`](../../SECURITY.md) had described GitHub private
vulnerability reporting as the preferred way to report a vulnerability. None
of it had been applied. Part of the reason nothing had broken in seven
sprints is that nothing could: the repo had never opened a pull request, so
the labeler workflow had never run on one (its config was in a schema
`actions/labeler` v7 rejects outright), and no check had ever been required of
anything.

The second half is persistence. Sprints 5, 11, and 12 have each added
`buildPg*Repository` implementations following
[ADR 0010](./0010-postgres-persistence.md): an interface, an in-memory default,
a plain-SQL `Queryable` implementation, and a `describe.each` suite running both
against `@electric-sql/pglite`. After Sprint 11, three of the thirteen backend
services had one (kubernetes, incident, security). Sprint 11's closeout listed
the remaining ten as a backlog — but listing them asserted that each one
_should_ be persisted, which was never checked.

## Decision

### Branch protection requires exactly one check: `Lint & Type-check`

`main` is protected with `required_status_checks.contexts = ["Lint & Type-check"]`,
`strict: false`, `enforce_admins: true`, force-pushes and branch deletion
blocked. PR review is **not** required and signed commits are **not**
required. Applied through the API, and recorded (with verification commands)
in `docs/operations/branch-protection.md`.

The one required check was chosen on a single criterion: **a required status
check is matched by exact context string, and GitHub reports a matrix job's
context per instance.**

- `Unit tests` is a matrix job over 17 workspaces
  (`.github/workflows/ci.yml`). GitHub reports each instance under its own
  name — `Unit tests (frontend)`, `Unit tests (backend/services/auth)`, … —
  so the bare string `Unit tests` matches no check at all. GitHub's own
  behaviour when a required context has never been reported is to leave the
  pull request in a state that looks mergeable, not to fail it: the gate is
  silently bypassed rather than loudly broken. That is the worst failure mode
  available for a security control, because the UI still shows a green
  "All checks have passed".
- Requiring all 17 instance names inverts the risk into brittleness rather
  than removing it: the next workspace added to the matrix would need its name
  registered, and omitting it fails safe (blocks a good merge) while
  mistyping one blocks every merge until noticed. That is survivable, but it
  means the security-relevant configuration has to be updated in lockstep with
  an unrelated CI change, forever.
- `Build` does run on `pull_request`; it appeared not to because it
  `needs: [lint, test-unit, test-python]` and its dependencies had not
  finished. A skipped-dependency cascade looks identical to an
  `if: github.event_name == 'push'` guard in the settings UI, which is a
  misleading thing to reason about.

`Lint & Type-check` is the one job with a name that does not vary per
instance, it runs on every push and every pull request, and it runs
`pnpm format:check`, `pnpm lint`, and `pnpm typecheck` — so format, lint, and
type errors all block. Test failures remain visible on the pull request and
block through review, which is where a human reads the diff anyway.

### Enabling a required check means `main` rejects direct pushes

A required check cannot run on a commit that is not on the remote. There is no
configuration in which "require a status check" and "accept direct pushes to
`main`" are both true. So the contribution workflow changed from
push-to-`main` to branch → push → pull request → merge, and Sprint 12's own
work went that way (PR #86).

This is stated here rather than left to be discovered, because the previous
workflow — documented in `CLAUDE.md` as commit, `git push origin main`, pause —
no longer works and will fail at the push step. The replacement is the
conventional one: the same commit, one review surface (the PR) instead of none,
and the lint/type gate enforced by the server rather than by the author
remembering to run it.

Deliberately _not_ enabled, and why:

- **Required PR review** — a solo maintainer cannot review their own work in a
  meaningful way; this would make every merge impossible rather than safer.
  Revisit when a second maintainer joins.
- **`strict` (require branches up to date)** — forces a rebase-and-retry loop
  on every merge, for a gate that only matters with concurrent reviewers.
- **Required signed commits** — depends on the maintainer configuring local
  commit signing, which has not happened yet.

### Persistence is decided per-state, not per-service

The rule applied: **persist a row only when a row is the source of truth.** If
the state is a cache of something that can be re-read from an authoritative
source, or a buffer of work in flight, it stays in memory.

Sprint 12 converted three of those ten — the ones whose state is genuinely
authoritative: integration (`integrations`, `syncs`), compliance (`controls`,
`evidence`), and auth (`users`) — using the ADR-0010 pattern unchanged. The
other seven were read and deliberately **not** converted:

- **`agent-service`.** The task queue (`src/services/task-queue.ts`) is a
  `Map<UUID, AgentTask>` plus an `order: UUID[]` FIFO: an in-flight work
  buffer, drained as agents pick tasks up. A persisted task row that outlived
  its process is a task no worker will ever claim — it would need a reaper to
  detect and re-enqueue it, at which point the row was never the source of
  truth, just a slower version of the same buffer.
- **`inventory`, `topology`, `cost-intelligence`, `k8s-health`,
  `runtime-security`, `reporting`.** Each derives its answers per request from
  Kubernetes API servers, Prometheus, or other services' APIs. A persisted row
  is a snapshot with a timestamp, and its only question is when it goes stale.
  For a security-posture surface, serving last week's findings is worse than
  serving none: the consumer cannot tell a stale answer from a current one,
  because the API contract is identical. Recomputation is the feature.

The same rule, applied inside compliance-service, decided that
**`FrameworkRepository` stays in-memory** while `ControlRepository` and
`EvidenceRepository` were converted. `FrameworkRepository` serves a
module-level `SUPPORTED` constant — four frameworks with metadata, no write
path, and a `list(_tenantId)` that ignores its tenant argument entirely. A
`frameworks` table would store a catalogue that nothing in the codebase mutates,
that would have to be re-migrated by hand every time a framework version
changed in code, and whose contents would be a _second_ source of truth
competing with the constant. The rule says persist the source of truth; here
the source of truth is the code, and it is already durable in git.

Converted vs not, after Sprint 12: kubernetes (`clusters`), incident
(`incidents`, `runbooks`, `chains`), security (`assets`, `scans`, `findings`,
`sboms` + component index), auth (`users`), integration (`integrations`,
`syncs`), and compliance (`controls`, `evidence`) have `buildPg*Repository`
implementations. `agent`, `inventory`, `topology`, `cost-intelligence`,
`k8s-health`, `runtime-security`, and `reporting` do not, by decision.

## Consequences

- `main` cannot be pushed to directly. Anyone scripting against the old
  workflow (`CLAUDE.md`'s "commit, `git push origin main`, pause") must move to
  branch + PR. This is the intended shape, and it is the reason the labeler
  config was fixed in the same pass — the workflow finally has pull requests
  to run on.
- The gate covers format, lint, and type errors, not test results. A red test
  on `main` is possible if a maintainer merges anyway. Accepted deliberately:
  a matrix-derived context list is either a silent bypass or a maintenance
  trap, and neither is worth having as the primary merge control.
- Enforcement now depends on repository settings, which are invisible in the
  working tree. `docs/operations/branch-protection.md` is the durable record,
  and it carries the two `gh api` commands to re-read the live state — if they
  and the document ever disagree, the document is stale.
- Adding a Postgres-backed repository remains a per-service decision against
  the source-of-truth rule, not a checklist to exhaust. The next candidate is
  compliance's POA&M repository, which _is_ authoritative (it is written by
  `POST /v1/poam` and by the mapping/evidence paths, and read back by
  `GET /v1/poam`), unlike everything left behind.
- Tenant scoping is unchanged and still per-query, not row-level security.
  `UserRepository` remains unscoped by tenant (`list`, `findById`,
  `findByEmail`, `setActive` take no `tenantId` in either implementation); the
  Pg conversion mirrored the existing signature rather than fixing it
  out-of-band.
- Private vulnerability reporting being on means a stranger can now open a
  private advisory. That is the point; `SECURITY.md` states there is no email
  fallback and the triage path.

## Note (verification limits)

The `DATABASE_URL`-set startup path is proven through `@electric-sql/pglite`
driving the identical `buildPg*Repository` code, **not** through a live
`pg.Pool`: the machine this sprint was developed on has no Docker, so no
`make up` against real Postgres was run. The repository-level SQL is
exercised; the pool's connection handling, `migrate()`'s client-pinning path,
and `db.end()` on shutdown are not. `security-service` has shipped the same
wiring since Sprint 11 without incident, but that is not evidence for these
three. A `make up` smoke against real Postgres is outstanding.

For the same reason, the three services converted in Sprint 12 do **not** add a
`/readyz` database probe; their health routes still check only the event bus,
as they did before. `security-service` has a `SELECT 1` readiness check. That
inconsistency is a known gap, not a design position.

The branch-protection and private-reporting settings, by contrast, were read
back from the GitHub API after being applied, and are not assertions.

## References

- `docs/operations/branch-protection.md` — applied settings and verification
  commands.
- `.github/workflows/ci.yml` — the job names and matrix this decision depends
  on.
- [ADR 0010](./0010-postgres-persistence.md) — the `Queryable` /
  in-memory-default / `migrate()` pattern the three conversions follow.
- `docs/architecture/sprint-12/README.md` — per-ticket detail.
