# 0010 — Postgres persistence for clusters, incidents, runbooks, chains

Status: accepted
Date: 2026-09-22

## Context

Sprint 4 shipped four in-memory, process-local repositories:
`ClusterRepository` (kubernetes-service), `IncidentRepository` and
`RunbookRepository` (incident-service), and `ChainRepository`
(incident-service's AI correlation engine). All state is lost on
restart, which is fine for a demo but not for Sprint 5's persistence
milestone.

## Decision

- **No ORM.** Repositories write plain SQL against a minimal
  `Queryable` interface (`{ query(text, params) => { rows } }`),
  satisfied by both `pg.Pool` (production) and `@electric-sql/pglite`
  (tests). `@aicc/shared/db` exports `createPool`, `Queryable`,
  `Migration`, and a ~30-line `migrate()` that tracks applied
  migrations in a `schema_migrations` table and applies the rest
  inside a transaction each.
- **Migrations are TypeScript modules**, not `.sql` files on disk
  (`src/db/migrations.ts` exporting `MIGRATIONS: Migration[]`). They
  compile into `dist/` with the rest of the service — no extra copy
  step, no runtime filesystem globbing.
- **jsonb-heavy schema.** Nested/variable-shape data (labels, runbook
  steps, incident chain event lists, correlation edges) lives in
  `jsonb` columns; only fields the in-memory `list()` filters or sorts
  on (`tenant_id`, `status`, `severity`, `created_at`) get real
  columns and indexes.
- **In-memory stays the default.** Every service picks its repository
  at startup: `cfg.databaseUrl ? buildPg...() : buildInMemory...()`.
  `DATABASE_URL` unset (the local dev / CI default) means zero Postgres
  dependency.
- **Tests run against PGlite**, an in-process WASM Postgres, so the Pg
  and in-memory implementations run the _same_ `describe.each` test
  suite with no Docker requirement. `migrate()` splits each migration's
  SQL on `;` before sending statements one at a time — PGlite's
  extended query protocol rejects multi-statement strings that `pg.Pool`
  accepts fine via the simple protocol.
- **Credentials stored in plain columns.** The kubernetes-service
  `clusters` table has `token`/`ca_bundle` text columns, matching the
  Sprint 4 in-memory behaviour exactly. Encryption-at-rest for these
  fields is a follow-up ticket, not in scope here. **Resolved in
  ADR-0016** (Sprint 6): AES-256-GCM envelope encryption into new
  `token_enc`/`ca_bundle_enc` columns, with the plain columns kept
  temporarily for backward compatibility.
- **The correlation buffer is not persisted.** `correlation-engine.ts`'s
  in-memory event buckets are a sliding time window used to _produce_
  chains, not a source of truth — only the resulting `IncidentChain`s
  and `CorrelationEdge`s (already handled by `ChainRepository`) need
  durability.

## Consequences

- Adding a fifth persisted entity means: one migration in the owning
  service's `src/db/migrations.ts`, one `buildPg<X>Repository`
  alongside the existing in-memory builder, and one `describe.each`
  test file — no shared migration framework to learn.
- Every Pg query filters by `tenant_id` explicitly (no row-level
  security yet); this mirrors the in-memory repositories' tenant checks
  and is the same trust boundary already documented in
  `docs/architecture/security-model.md` §3.4.
