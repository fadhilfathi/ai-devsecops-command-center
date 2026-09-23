# 0017 — Fastify 4 → 5

Status: accepted
Date: 2026-09-23

## Context

Fastify v4 has been unsupported (EOL) since mid-2025 and `pnpm audit`
flagged high/moderate/low advisories against `fastify@4.29.1` plus
`@fastify/static` (pulled in transitively by `@fastify/swagger-ui@4.2.0`
in `security-service`). Sprint 7 (S7-2) is a general dependency /
supply-chain pass; this is the backend-facing half of it.

## Decision

Upgrade `fastify` to `^5.12.5` across every workspace that depends on
it — all 13 backend services, `@aicc/shared`, `@aicc/observability` —
and the matching plugin majors: `@fastify/cors` 11, `@fastify/helmet`
13, `@fastify/sensible` 6, `@fastify/swagger` 9, `@fastify/swagger-ui`
6 (this also resolves the `@fastify/static` advisories), `@fastify/rate-limit`
11, `pino` 10, `pino-pretty` 13. One version per package across the
whole workspace.

### Breaking changes actually hit

Grepped for every breaking change in the Fastify 5 migration guide;
only two were live in this codebase:

1. **Custom logger option renamed.** Every service's `src/index.ts`
   passed an already-constructed pino instance as `Fastify({ logger })`
   (deliberately, per Sprint 5, to get one structured logger shared
   between the app and the framework). In v5 that option is
   `loggerInstance`; `logger` now only accepts `true`/`false`/pino
   options to have Fastify construct its own. Fixed in all 13
   `src/index.ts` files (`logger: logger` / `logger,` →
   `loggerInstance: logger,`).
2. **`setErrorHandler`'s error type defaults to `unknown`** (was
   `FastifyError`), so `err.statusCode`/`err.code`/`err.message` no
   longer type-check without an explicit generic. Fixed in the same 13
   files: `server.setErrorHandler<FastifyError>((err, req, reply) => ...)`.

### Breaking changes checked and already compliant

- `request.routerPath`/`routeConfig` — the shared `@aicc/observability`
  metrics plugin already used `req.routeOptions?.url` (added ahead of
  this migration).
- `decorateRequest` with reference-type defaults now throws — every
  service already decorates `tenantId`/`userId` with `''` (string
  primitives), not an object/array default.
- `reply.redirect(code, url)` → `reply.redirect(url, code)` — no route
  calls `reply.redirect(...)` anywhere in the codebase.
- Full JSON Schema required for `querystring`/`params`/`body` (no more
  shorthand) — every route already writes
  `{ type: 'object', properties: {...} }` in full.
- `jsonShorthand` removal, `getResponseTime()` → `elapsedTime`,
  `hasRoute` signature change, `useSemicolonDelimiter` default —
  none of these were used anywhere in the codebase.

## Consequences

- No behavior change for API consumers; this is an internal-dependency
  bump.
- `pnpm audit` after the full S7-2 pass (Fastify 5 + vitest 4 +
  react-router 7): 0 critical / 0 high / 0 moderate / 0 low.
- Future Fastify majors: repeat the grep-for-breaking-changes approach
  above rather than assuming; most of the "breaking changes" list for
  v5 never touched this codebase because Sprint 2's metrics plugin and
  Sprint 5's auth-decoration already used the v5-shaped APIs.
