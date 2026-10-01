# Sprint 12 — Release readiness: repository settings, three more services on Postgres

Sprint 12 turned the repository's release-readiness checklist into applied
settings and finished the Postgres pass over the services whose state is
actually worth keeping. No product behaviour changed — every route, contract,
and event payload is as Sprint 11 left it.

## Applied repository settings (S12-1)

`docs/operations/branch-protection.md` had been a manual checklist since
Sprint 7. It is now the record of what is actually enabled on `main`
(verified with `gh api repos/fadhilfathi/ai-devsecops-command-center/
branches/main/protection`):

- **Required status check: `Lint & Type-check` only.** `strict: false`,
  `enforce_admins: true`, force-pushes blocked, branch deletion blocked.
- **Private vulnerability reporting is enabled.** `SECURITY.md` described it
  as the preferred way to report a vulnerability; the setting itself had never
  been turned on. Verified with
  `gh api repos/.../private-vulnerability-reporting` → `{"enabled":true}`.

Only one check is required, deliberately. `Unit tests` is a **matrix** job
(17 workspaces in `.github/workflows/ci.yml`), so GitHub reports its check
names per instance — `Unit tests (frontend)`,
`Unit tests (backend/services/auth)` — and requiring the bare context string
`Unit tests` never matches anything, which silently bypasses the gate instead
of enforcing it. Requiring all 17 instance names is brittle in the other
direction: the next workspace added to the matrix would need its name
registered or the gate quietly stops covering it. `Build` does run on PRs
(`on: pull_request`), but it `needs: [lint, test-unit, test-python]`, so its
absence on an open PR is a skipped-dependency cascade rather than a push-only
guard. `Lint & Type-check` is the one job that runs on every PR under a name
that does not vary, and it runs `pnpm format:check`, `pnpm lint`, and
`pnpm typecheck` — so format, lint, and type errors all block a merge. Test
failures stay visible on the PR and block through review, just not as a hard
gate. PR review itself is not required (solo maintainer), so a PR can still be
self-merged; signed commits are off until local signing is configured.

**This changed how work lands.** A required check cannot run on a commit that
is not on the remote, so `main` no longer accepts direct pushes — the
contribution flow is now branch → push → PR → merge. Sprint 12's own work
went that way (PR #86). That is the intended effect, not an obstacle.

> **Note (doc scope).** Sprint 12's code landed in PR #86. This file was
> written afterwards, as the sprint's closeout documentation, and rewords the
> already-merged `ROADMAP.md` and `CHANGELOG.md` entries. The release-readiness
> settings were applied as part of that PR (#86) — read this file as the
> narrative for that work, not as a record of a second change.

Three smaller fixes came out of the same pass:

- **PyJWT `2.14.0 → 2.15.1`** in
  `agents/roles/security/vuln-intel/pyproject.toml`; the old pin did not cover
  CVE-2026-101918. `pip-audit --local` in that agent no longer reports any
  PyJWT finding (it does still report findings for `aiohttp`,
  `cryptography`, `h2`, `setuptools`, `urllib3`, `yt-dlp`, and `torch` — this
  bump was scoped to PyJWT, not a clean audit).
- **`.github/labeler.yml`** migrated from the flat v2 label form to the v5+
  `any-glob-to-any-file` schema required by `actions/labeler` v7. The old file
  was rejected outright ("found unexpected type for label 'frontend'"), which
  went unnoticed only because no pull request had ever existed for the workflow
  to run on.
- **`SECURITY.md`'s supported-version table** said `0.1.x`; the project is at
  `0.7.0` (`package.json`), so the table now reads `0.7.x` / `0.6.x` /
  `< 0.6` EOL, matching the rolling-window rule stated above it.

## integration-service on Postgres (S12-2)

`integrations` and `syncs` tables
(`backend/services/integration/src/db/migrations.ts`) with
`buildPgIntegrationRepository` and `buildPgSyncRepository`
(`src/repositories/integration.repository.ts`,
`src/repositories/sync.repository.ts`). `Integration.config` and
`SyncRecord.metadata` are `jsonb`; the row mappers parse a string result
defensively (`typeof row.config === 'string' ? JSON.parse(...) : row.config`)
so the same code works whether the driver hands back an object or text.

Tenant scoping is in the SQL (`WHERE id = $1 AND tenant_id = $2` on every
single-row lookup and update), the optional `framework` / `integrationId` /
`status` list filters are appended as numbered conditions rather than
interpolated, and mutating methods use `RETURNING *` so a foreign-tenant
update returns `undefined` instead of silently succeeding. Indexes cover
`tenant_id`, `integration_id`, and `(tenant_id, status)` — the columns the
routes actually filter on.

This is the state S11-2 depends on: a GitHub PAT on an integration, and the
`github.remediation` sync rows the remediation audit trail reads, now survive
a restart. The `config` column is still written exactly as supplied, so the
ADR-0021 encrypt-on-write gap is unchanged (the read path still decrypts via
the ADR-0016 keyring).

## compliance-service on Postgres (S12-3)

`controls` and `evidence` tables with `buildPgControlRepository` and
`buildPgEvidenceRepository` (`src/repositories/control.repository.ts`,
`src/repositories/evidence.repository.ts`), plus a composite index on
`(tenant_id, control_id, ref)` — `EvidenceRepository.findByRef` is the dedup
lookup `EvidenceAttacher` uses before writing a row
(`src/evidence/evidence-attacher.ts`).

`ControlRepository.addEvidence` is the one place where the naive port would
have been wrong. It has to stay idempotent (the in-memory version returns the
control untouched when the ref is already present), and the obvious port is a
`SELECT` then a write — a read-modify-write that loses a concurrent append and
rereads a row it just wrote. Instead the append is a single `UPDATE` with a
`jsonb` containment test:

```sql
evidence_refs = CASE
  WHEN evidence_refs @> $3::jsonb THEN evidence_refs
  ELSE evidence_refs || $3::jsonb
END
```

`@>` is the "contains" operator, so the branch is decided by the database
inside the same statement that would write — one round trip, no lost update,
and `updated_at` moves only when the ref was actually new (same `CASE`).
Both implementations are pinned by the same `describe.each` suite.

`FrameworkRepository` deliberately has **no** Postgres version, unlike the
other two repositories in the same service. It is a module-level `SUPPORTED`
constant array of four frameworks (CIS v8, NIST 800-53, SOC 2, ISO 27001) with
no write path, no per-tenant state, and `list(_tenantId)` ignoring the tenant
entirely; `supported()` returns the same array. A table would store a
catalogue nothing mutates and that would have to be migrated by hand whenever
a framework version changed in code. `framework.repository.test.ts` pins the
property that makes this safe (identical output for every tenant, unchanged
across reads). See
[ADR 0022](../../adr/0022-release-readiness-gate-and-persistence-scope.md).

The POA&M repository (`src/poam/poam.repository.ts`) is also still in-memory —
it is the one genuinely durable-looking store left in this service and is a
sensible next conversion.

## auth-service on Postgres (S12-4)

A `users` table with `email text NOT NULL UNIQUE`, an index on `tenant_id`,
and `buildPgUserRepository` (`src/services/user.repository.ts`).

The migration seeds the same platform-admin row the in-memory builder seeds
(`00000000-0000-4000-8000-000000000001`, tenant
`…000000000000`, `admin@aicc.local`, role `platform_admin`,
`ON CONFLICT (id) DO NOTHING`). The seed lives in the migration on purpose:
`POST /v1/auth/dev-login` looks a user up by email and 404s on a miss, and that
is the only login path in the platform, so a freshly migrated database has to
be immediately usable. The `UNIQUE` email constraint is a real behavioural
difference from the in-memory map, and it is pinned by a PGlite-only test that
asserts the second insert rejects.

**No password column and no hashing were added.** `User` carries no password
field, `CreateUserInput` has none, and neither implementation hashes anything —
`dev-login` is still a password-less email lookup. Adding a credential store
is a separate feature with its own decisions (hash algorithm, reset flow,
lockout), not something to smuggle in alongside a schema migration.

## Deliberately not converted to Postgres

Sprint 11's closeout listed "the remaining in-memory-only services" as a
backlog. Reading each one showed most of that list is state that _should not_
be persistent:

- `agent-service` — the task queue (`src/services/task-queue.ts`) is a
  `Map<UUID, AgentTask>` plus an `order: UUID[]` FIFO array: an in-flight work
  buffer. A task row that outlived its process would be a task nobody is
  draining. Recomputing (re-enqueue) is the correct recovery.
- `inventory`, `topology`, `cost-intelligence`, `k8s-health`,
  `runtime-security`, `reporting` — each derives its answers on request from
  Kubernetes API servers, Prometheus, or other services' APIs. A persisted row
  is a snapshot with a timestamp, and the only question is when it goes stale.
  For a security posture view, showing last week's finding is worse than
  showing none, so these stay recomputed.

Of the 13 backend services, 7 now have `buildPg*Repository` implementations:
kubernetes (clusters), incident (incidents, runbooks, chains), security
(assets, scans, findings, SBOMs + component index), auth, integration, and
compliance. See [ADR 0022](../../adr/0022-release-readiness-gate-and-persistence-scope.md)
for the boundary that decides which is which.

## How to run it

Unchanged from Sprint 10/11 — nothing about local startup moved:

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

`DATABASE_URL` is the only new switch. Unset (the default for `pnpm dev` and
for the tests) keeps every service in-memory; set, it selects the Pg
repository and runs that service's migrations at startup. The three converted
services each ship a per-service example:

```bash
# backend/services/{auth,compliance,integration}/.env.example
DATABASE_URL=postgres://aicc:aicc@localhost:5432/aicc_{auth,compliance,integration}
```

`docker-compose.yml` already points these three containers at their own
databases (`aicc_auth`, `aicc_compliance`, `aicc_integration`, created by
`infra/docker/init/postgres-databases.sql`), so `make up` needs no edit — the
environment was already there from the Sprint 5 compose work.

## What is verified, and what is not

Verified in the working tree:

- Every `buildPg*Repository` runs the same `describe.each` suite as its
  in-memory twin against `@electric-sql/pglite` (an in-process WASM Postgres),
  including tenant isolation on every read and write, the `jsonb` idempotent
  `addEvidence`, and the `findByRef` dedup lookup. No Docker needed.
- The auth tests drive `buildPgUserRepository` through the real Fastify
  server: `POST /v1/auth/dev-login` against a freshly migrated PGlite database
  returns a token for the seeded admin and 404s an unknown email.
- The repository settings in `docs/operations/branch-protection.md` were read
  back from the GitHub API (see the `gh api` commands in that file), not
  assumed.
- `pip-audit --local` in `vuln-intel` reports no PyJWT finding at 2.15.1.

**Not verified — outstanding:**

- **No live-Postgres smoke.** The development machine has no Docker, so the
  `DATABASE_URL`-set startup path is proven through `@electric-sql/pglite`
  driving the identical `buildPg*` code, never through a real `pg.Pool`. The
  `pg.Pool` connection, `migrate()`'s client-pinning path, and `db.end()` on
  shutdown are therefore **not** exercised for these three services.
  **A `make up` smoke against real Postgres is still outstanding** and should
  be the first thing a maintainer runs.
- The three services do **not** add a `/readyz` DB probe. `security-service`
  has one (`SELECT 1` in its health routes); auth, compliance, and integration
  check only the event bus, matching their pre-Sprint-12 behaviour. A service
  whose pool cannot reach Postgres will report ready. Worth adding for
  consistency.
- The `pnpm vitest --testTimeout=30000` bump in those three packages is only
  because the PGlite migrations are slow on first run; no test was weakened.
- Every other service's persistence story was reviewed by reading its code,
  not by running it.

## Still deferred

- Real credential-based authentication — auth-service still has only the
  password-less `dev-login`. This is the largest gap between the code and a
  production deployment.
- Tenant scoping on `UserRepository`: `list`, `findById`, `findByEmail`, and
  `setActive` take no `tenantId` in either implementation. A pre-existing gap
  that the Pg conversion deliberately mirrored rather than fixing
  out-of-band (same call as S11-4's `ScanRepository.updateStatus`).
- POA&M persistence in compliance-service.
- Encrypt-on-write for the integration `config` token (ADR 0021's note).
- A `/readyz` DB probe in the three services converted this sprint.
- A live-Postgres `make up` smoke.
- Required PR review and required signed commits — both deliberately off for a
  solo maintainer; revisit when a second maintainer joins or local commit
  signing is configured.

## Next steps

Release 1.0 readiness: credential-based auth first, then the Postgres smoke.
See `ROADMAP.md`.
