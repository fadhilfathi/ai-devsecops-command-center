# 0018 — HTTP hardening: CORS allow-list, strict API CSP, body + rate limits

Status: accepted
Date: 2026-09-24

## Context

Every service's `buildServer()` repeated the same bootstrap:
`cors({ origin: true, credentials: true })` (reflects any `Origin` back
with credentials — the exact CORS misconfiguration that lets any
website read authenticated responses cross-origin), `helmet({
contentSecurityPolicy: false })`, no body-size limit beyond Fastify's
1 MiB default, and rate limiting only in `security-service`. S7-4
closes this gap.

The browser never talks to a backend service directly: `frontend/
proxy-table.mjs` generates both `vite.config.ts`'s dev proxy and
`nginx.conf`'s production proxy, so the SPA always reaches every
service same-origin via `/api/*`. Cross-origin browser access is not a
requirement today — it's opt-in for the future (a separate frontend
deployment, a partner integration, etc.), not the default.

## Decision

Added `registerSecurityPlugins(server, cfg, opts?)` to
`@aicc/shared/http`, replacing the 13 duplicated
helmet/cors/sensible(/rate-limit) blocks. Every service calls it right
after constructing its Fastify instance and before the auth hook.

- **CORS**: no `@fastify/cors` plugin registered at all unless
  `CORS_ORIGINS` (comma-separated exact origins) is set — no service
  echoes `Access-Control-Allow-Origin` by default. When set, it's a
  strict allow-list (`origin: string[]`), never `origin: true`.
- **helmet**: `contentSecurityPolicy: { directives: { defaultSrc:
["'none'"], frameAncestors: ["'none'"] } }` — every service here is a
  JSON API, so it serves no HTML and needs no script/style/img
  sources. `security-service`'s Swagger UI (`/docs`) is the one
  exception: `registerSecurityPlugins` accepts `cspRelaxedPrefixes`,
  which overrides the CSP header via an `onSend` hook for matching
  path prefixes instead of disabling CSP service-wide. HSTS on,
  `crossOriginResourcePolicy: same-site`, `referrer-policy: no-referrer`.
- **Body limit**: `BODY_LIMIT_BYTES` (default 1 MiB) passed as
  Fastify's constructor `bodyLimit` — it can't be set by a plugin
  after the instance exists. Routes with legitimately larger payloads
  get an explicit per-route `bodyLimit` override:
  - `security-service`: `POST /v1/sboms`, `POST /sbom/generate`,
    `POST /sbom/analyze`, `POST /vulnerabilities/ingest` — 10 MiB (a
    CycloneDX/SPDX document or a bulk vulnerability batch routinely
    exceeds 1 MiB).
  - `integration-service`: `POST /v1/webhooks/:provider` — 5 MiB
    (webhook payloads, e.g. full SARIF/scan payloads); moved from the
    Fastify constructor (which applied it service-wide) to the route
    itself, so every other route on that service gets the shared
    1 MiB default (S7-4).
- **Rate limit**: `@fastify/rate-limit`, global, `RATE_LIMIT_MAX` per
  `RATE_LIMIT_WINDOW` ms (default 300/60s), registered with `hook:
'preHandler'` so it evaluates after the auth `onRequest` hook every
  service adds afterwards — `keyGenerator: req.userId || req.ip` needs
  the verified user id, not just the IP, and `preHandler` hooks run
  (app-wide) after all `onRequest` hooks regardless of plugin
  registration order. `/healthz`, `/readyz`, `/metrics` are always
  exempt (`isRateLimitExempt`, exported so `security-service`'s own
  rate limit — see below — exempts the same paths). `auth-service`'s
  `POST /v1/auth/dev-login` and `POST /v1/auth/refresh` get a tighter
  per-route override (10/min) via Fastify's `config: { rateLimit }`
  route option — the credential-stuffing/brute-force surface.
  `security-service` keeps its own `@fastify/rate-limit` registration
  (10 req/s default, metrics-instrumented via
  `rateLimitRejectionsTotal`) instead of the shared one —
  `registerSecurityPlugins(server, cfg, { installRateLimit: false })`
  — so `installRateLimit` exists specifically for that one caller.
- **`trustProxy`**: Fastify 5 removed numeric hop-count trust ("it
  cannot validate the immediate peer, so a direct client could spoof
  it" — see the framework's own docs). The replacement is an IP/CIDR
  allow-list: `TRUST_PROXY_CIDR` (default
  `127.0.0.1,172.28.0.0/16`), covering the vite dev proxy on loopback
  and the docker-compose `ccnet` network, which is now pinned to
  `172.28.0.0/16` in `docker-compose.yml` (Docker's auto-assigned
  bridge subnet is not stable across hosts/restarts, so the default
  had to be pinned rather than guessed). `X-Forwarded-For` from
  outside that list is ignored, so it can't be used to spoof the
  rate-limit key. nginx (`frontend/scripts/gen-nginx.mjs`) is the edge
  today — nothing sits in front of it — so every proxied `location`
  block _overwrites_ `X-Forwarded-For`/`X-Real-IP` with `$remote_addr`
  (and sets `X-Forwarded-Proto $scheme`) rather than appending to
  whatever the browser sent, otherwise a client could rotate its own
  rate-limit key by forging that header — nginx would forward it
  unchanged, and it originates inside `TRUST_PROXY_CIDR` so Fastify
  would trust it. If a load balancer is ever placed in front of nginx,
  this must change to `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;` (append, not overwrite) plus adding the
  LB's address to nginx's own `set_real_ip_from`, so nginx's view of
  the "real" client IP comes from the LB instead of the raw TCP peer.

## Consequences

- Every service now defaults to same-origin-only; enabling
  cross-origin access for a new consumer is a one-line `CORS_ORIGINS`
  change, not a code change.
- A misconfigured/missing `TRUST_PROXY_CIDR` in a future non-Docker
  deployment (e.g. a different reverse proxy IP range) will silently
  fall back to trusting only loopback + the compose subnet — `req.ip`
  degrades to the proxy's IP rather than the real client's, which is
  safe (rate limits get coarser, not spoofable) but worth knowing.
- `security-service`'s own per-route rate limit env vars were renamed
  to `SECURITY_INGEST_RATE_LIMIT_MAX`/`SECURITY_INGEST_RATE_LIMIT_WINDOW_MS`
  (S7-4) — they previously collided in name (though not in effect,
  each was read from its own `EnvSchema`/`loadServiceConfig` module)
  with the shared global `RATE_LIMIT_MAX`/`RATE_LIMIT_WINDOW`, which
  was confusing enough to fix outright rather than leave a footnote.

## Out of scope

No WAF, no per-tenant quotas (rate limiting is per-process, in-memory
— a Redis-backed store would be needed for multi-instance accuracy),
no CSRF tokens (cookie-based sessions aren't used — every request
carries a bearer token), no mTLS between services.
