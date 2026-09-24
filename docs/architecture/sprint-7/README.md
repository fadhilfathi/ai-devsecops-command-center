# Sprint 7 — Architecture Notes

Sprint 7 was a hardening sprint: no new product surface, just closing
the gaps Sprint 6 left open — lint debt, an EOL Fastify major with
open advisories, four broken CI workflows, a duplicated and
under-hardened HTTP bootstrap on every service, and a compose stack
that had never been exercised end to end.

## Lint zero, `--max-warnings 0` (S7-1)

Cleared all 45 outstanding ESLint warnings
(`@typescript-eslint/no-unused-vars`, `@typescript-eslint/no-explicit-any`,
unused `eslint-disable` directives) at the root — dead imports/functions
deleted, `any` replaced with real types, `evidence-attacher.ts`'s
`MappingInput` construction typed directly instead of cast. Along the
way this surfaced a real bug: `inventory-service`'s
`/v1/inventory/graph/asset` route assigned the internal `AssetKind`
(e.g. `'deployment'`) straight to a `TopologyNode`'s `kind` field
instead of going through the existing `toNodeKind()` mapper, producing
invalid node kinds in the asset graph. `pnpm lint` now runs with
`--max-warnings 0` in CI so the count can't silently grow back.

## Dependency / supply-chain pass (S7-2)

Fastify 4→5 across all 13 backend services plus `@aicc/shared` and
`@aicc/observability` — Fastify 4 was EOL with open advisories, and
`@fastify/static` (pulled in transitively by `security-service`'s
Swagger UI) had its own. Two real breaking changes hit: the custom
logger option renamed to `loggerInstance`, and `setErrorHandler`'s
error type now defaults to `unknown` instead of `FastifyError`. Fixed
in all 13 `src/index.ts` files. Matching plugin majors bumped
(`@fastify/cors` 11, `@fastify/helmet` 13, `@fastify/sensible` 6,
`@fastify/swagger` 9, `@fastify/swagger-ui` 6, `@fastify/rate-limit`
11, `pino` 10, `pino-pretty` 13) — one version per package
workspace-wide. Also bumped vitest 2→4 (requires vite 5→7,
`@vitejs/plugin-react` 4→5) and react-router-dom 6→7 in the frontend
(declarative mode, no API changes needed), `pyjwt` to 2.13.0 in
`vuln-intel`, `pytest` to 9 in `dependency-intel`.

`pnpm audit`: 21 advisories (2 critical / 5 high / 13 moderate / 1
low) before this sprint → 0 across the board after. Dependabot
consolidated from 8 overlapping npm entries to one root
pnpm-workspace-aware entry, plus grouped `pip` entries for the 3
Python security agents. See [ADR 0017](../../adr/0017-fastify-5.md).

## Every workflow green (S7-3)

Four workflows (`sbom`, `security`, `scorecard`, `codeql`) had been
failing on every push to `main` for weeks. Root causes: `security.yml`
and `security-issue.yml` were dead GitOps automation from a deleted
multi-agent era — no producer ever existed for their
`repository_dispatch` triggers, nor for the `attach-sbom` job in
`release.yml` that depended on them; deleted all three. The remaining
workflows had stale action versions and missing permissions rather
than a logic bug.

Every third-party action across every workflow is now pinned to a
commit SHA (with a `# vX.Y.Z` comment; Dependabot keeps them current)
instead of a mutable tag. Every workflow/job got least-privilege
`permissions:` and `persist-credentials: false` on every non-pushing
checkout. `scorecard.yml` gained a `github/codeql-action/upload-sarif`
step.

The `release` workflow's `standard-version` step rewrote
`CHANGELOG.md` and pushed a bot commit to `main` on every run —
disallowed under this repo's no-bot-commits rule. Replaced with a
`workflow_dispatch`-only tag-and-publish flow: no commits, the
`CHANGELOG.md` section is hand-written before tagging. Removed
`standard-version` and the `release`/`release-dry` Make targets
accordingly.

`SECURITY.md` was rewritten to drop fictional teams, SLAs, and PGP-key
references and describe only automation that actually exists (`sbom`,
`codeql`, `scorecard`, Dependabot). Added
`docs/operations/branch-protection.md` — a manual checklist for the
maintainer, not yet applied, not enforced by CI. Deleted the stale
`docs/runbooks/security-automation.md` runbook (described
`security.yml`/`security-issue.yml`/a `github-bridge` service that
never existed) and trimmed `security/README.md` to just the
wire-format schema contracts; fixed the same stale references in
`docs/architecture/event-bus.md`.

## Shared HTTP hardening (S7-4)

Every service's `buildServer()` repeated the same bootstrap:
`cors({ origin: true, credentials: true })` (reflects any `Origin`
back with credentials — the exact misconfiguration that lets any
website read authenticated responses cross-origin), `helmet({
contentSecurityPolicy: false })`, no body-size limit beyond Fastify's
1 MiB default, and rate limiting only in `security-service`.

Added `registerSecurityPlugins(server, cfg, opts?)` to
`@aicc/shared/http`, replacing all 13 duplicated blocks:

- **CORS**: no `@fastify/cors` plugin registered at all unless
  `CORS_ORIGINS` is set — a strict allow-list, never `origin: true`.
  The SPA is same-origin via `/api/*` already (`frontend/
proxy-table.mjs` generates both the dev proxy and `nginx.conf`), so
  cross-origin access is opt-in for a future need, not the default.
- **helmet**: `default-src 'none'`, `frame-ancestors 'none'` CSP —
  every service here is a JSON API. `security-service`'s Swagger UI
  (`/docs`) is the one exception, relaxed per-path-prefix via an
  `onSend` hook rather than disabling CSP service-wide.
- **Body limit**: `BODY_LIMIT_BYTES` (default 1 MiB) at the Fastify
  constructor, with explicit 10 MiB per-route overrides on SBOM
  ingest/generate/analyze and vulnerability ingest, and 5 MiB on
  integration-service's webhook route.
- **Rate limit**: global `@fastify/rate-limit`
  (`RATE_LIMIT_MAX`/`RATE_LIMIT_WINDOW`, default 300/60s) keyed by
  verified user id (falling back to IP), exempting
  `/healthz`/`/readyz`/`/metrics`, with a tighter 10/min override on
  auth-service's login/refresh routes. `security-service` keeps its
  own pre-existing metrics-instrumented rate limit instead of the
  shared one.
- **`trustProxy`**: Fastify 5 removed numeric hop-count trust as
  spoofable; replaced with an IP/CIDR allow-list
  (`TRUST_PROXY_CIDR`, default `127.0.0.1,172.28.0.0/16`) — the
  docker-compose network is now pinned to that subnet rather than
  Docker's unstable auto-assigned bridge.

Review caught a real spoofing bypass in the first cut: nginx was
forwarding whatever `X-Forwarded-For`/`X-Real-IP` the browser sent
instead of overwriting it with `$remote_addr`, and since nginx itself
sits inside `TRUST_PROXY_CIDR`, Fastify would have trusted a
client-forged header — letting a client rotate its own rate-limit key
at will. Fixed by having every nginx proxied `location` block
overwrite (not append to) those headers. See
[ADR 0018](../../adr/0018-http-hardening.md).

## Compose end-to-end smoke test (S7-5)

`scripts/e2e-smoke.mjs` mints its own HS256 access token, waits for
every service's (and the frontend's) `/healthz`, hits one
authenticated route per service, `/readyz` on the Postgres/Redis-backed
services, two negative-auth cases (no token, wrong secret), and the
nginx `/api/*` proxy — the first time the full compose stack has been
exercised end to end rather than per-service in isolation.
`.github/workflows/e2e.yml` runs it against a freshly built stack on
every push to `main`, weekly, and on demand.

This surfaced a real bug: cost-intelligence's and topology's HTTP
kubernetes-service inventory provider only sent `x-tenant-id`, no
`Authorization` header, so the cross-service call 401'd whenever
`AUTH_DEV_BYPASS=false` — exactly the compose default. Both now mint a
short-lived internal service token per request using the shared HS256
secret.

The observability toolchain (Prometheus, Alertmanager, Grafana, Loki,
OTel collector) moved behind a compose `observability` profile since
it isn't needed to run or smoke the app — see `infra/README.md`. The
default `docker compose up` (and the e2e run) skips it.

The first real run of the compose stack (not just per-service unit
tests) exposed a batch of boot bugs that development on Windows had
hidden: services never started on Linux (`isMain` compared
`file:///` against `argv`, a Windows-only match — fixed with
`pathToFileURL`); `@aicc/shared` compiled to CommonJS (missing
`"type": "module"`) so its ESM named imports failed at runtime;
auth- and security-service rejected `EVENT_BUS_DRIVER=redis` against a
stale local enum; the frontend healthcheck probed `localhost`
(resolves to `::1`) while nginx listens IPv4 only; and
cost-intelligence/topology called kubernetes-service with no
`Authorization` header. All fixed (see the Fixed section of
[CHANGELOG.md](../../../CHANGELOG.md) `0.4.0`).

The e2e workflow boots all 13 services plus the frontend and passes,
first in development mode on `da47506` and then with
`NODE_ENV=production` (secret-strength, keyring and dev-login checks
active) on `d1a0683`.

## How to run it

Same as Sprint 6 — nothing in the local dev loop changed:

```bash
pnpm install
pnpm --filter @aicc/kubernetes-service dev   # etc., per service
cd frontend && pnpm dev                       # mocks on by default
```

or the full containerised stack, including the new e2e path:

```bash
docker compose up --build
node scripts/e2e-smoke.mjs
```

## Manual steps for the maintainer

- Apply the branch protection checklist in
  [`docs/operations/branch-protection.md`](../../operations/branch-protection.md)
  under Settings → Branches — nothing in CI enforces it yet.
- Enable GitHub's private vulnerability reporting (Settings →
  Security → Reporting) so `SECURITY.md`'s documented disclosure path
  actually works.

## Still deferred

- Dependabot's remaining major-version PRs are real, not noise: React
  19 (+ `react-dom`, `@types/react*`), Tailwind 4, TypeScript 6,
  `recharts` 3, `zustand` 5 — each needs its own migration pass, not a
  blind merge.
- No dead-letter queue or `XAUTOCLAIM` reclaim for the Redis Streams
  event bus (unchanged from Sprint 6).
- Auth is still HS256 with one shared secret across services; no
  RS256/JWKS.
- No per-tenant rate-limit quotas — the global limiter is per-process,
  in-memory, keyed by user id, not tenant-isolated.
- No WAF in front of nginx.

See [ADR 0017](../../adr/0017-fastify-5.md) and
[ADR 0018](../../adr/0018-http-hardening.md).

## Next steps (Sprint 8)

See `ROADMAP.md`.
