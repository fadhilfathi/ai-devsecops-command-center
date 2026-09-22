# 0013 — Service-to-service auth

Status: accepted
Date: 2026-09-22

## Context

Every service trusted a raw `x-tenant-id` (and `x-user-id`) header set
straight from `req.headers` in an `onRequest` hook — any caller could
impersonate any tenant. auth-service already issued HS256 JWTs
(`POST /v1/auth/dev-login`) and security-service already had a richer
(but per-service, non-enforcing) JWT-verification middleware; neither
was wired to reject unauthenticated requests service-wide.

## Decision

- **Single shared implementation.** `@aicc/shared/auth` exports
  `signAccessToken` / `verifyAccessToken` (HS256, constant-time
  signature compare, checks `exp`/`nbf`/`iss`/`aud`/required claims)
  and `buildAuthHook()`, a Fastify `onRequest` hook every service wires
  in `buildServer()`. It sets `req.tenantId` / `req.userId` /
  `req.userRole` from the verified token's claims — never from a
  client-supplied header. auth-service issues with the same function;
  every other service (including security-service, which previously
  had its own copy) verifies with it. security-service's RBAC
  (`requireRole`, `requireTenantMatch`) stays — it's a layer on top of
  the now-enforced authentication, not a replacement for it.
- **HS256 shared secret now, RS256/JWKS later.** One symmetric secret
  (`AUTH_JWT_SECRET`) configured identically across every service via
  `loadServiceConfig()` (`@aicc/shared/http`) is enough for a
  single-deployment-unit system with zero external cost. Moving to
  RS256 + a JWKS endpoint on auth-service (so services fetch a public
  key instead of sharing a secret) is a mechanical follow-up once
  services deploy independently trust domains; nothing in the shared
  module's call sites needs to change (`verifyAccessToken`'s signature
  is already parameterised on `{ secret, issuer, audience }`).
- **`AUTH_DEV_BYPASS`, on by default outside production.** When set (or
  defaulted true for `NODE_ENV !== 'production'`), a request with _no_
  `Authorization` header falls back to trusting `x-tenant-id`/
  `x-user-id` — this is what keeps every existing dev workflow, curl
  command, and test fixture working without minting a token. A
  present-but-invalid token is always rejected, bypass or not — bypass
  only covers the "no token at all" case. docker-compose sets
  `AUTH_DEV_BYPASS=false` so the local stack exercises real auth
  end-to-end; every service's `.env.example` documents the flag.
- **Production refuses the default secret.** `loadServiceConfig()`
  throws at startup if `NODE_ENV=production` and `AUTH_JWT_SECRET` is
  still the shared dev default — a service can boot without auth
  working by accident in dev, never in prod.
- **Frontend sends `Authorization: Bearer`, falls back to the legacy
  tenant header when logged out.** `frontend/src/lib/auth.ts` wraps
  auth-service's `POST /v1/auth/dev-login` (still the only login entry
  point — the user repository is seed-only with no password hashes) and
  keeps the token in memory + `sessionStorage`. The mock UI
  (`VITE_USE_MOCKS=true`, the default) bypasses the login gate entirely
  so the dashboard still renders with no backend running.

## Amendment (2026-09-22, S6-2 follow-up)

The initial cut wired `buildAuthHook()` service-wide but left most
route handlers reading `req.headers['x-tenant-id']`/`['x-user-id']`
directly instead of the hook-verified `req.tenantId`/`req.userId` — a
valid token for tenant A plus a forged `x-tenant-id: <tenant-B>` header
still read tenant B's data end to end. Fixed across every route file
in incident-, integration-, security-, compliance-, and agent-service
(the last also dropped `tenantId` from its request body — it must
never come from client input, header or body). Tenant identity is now
exclusively the verified token's `tenantId` claim; the only remaining
reads of the raw header are the shared `devBypass` fallback in
`buildAuthHook` itself (no-token case only) and security-service's
`requireTenantMatch`, which reads the header purely to reject a
mismatch, never to trust it.

`POST /v1/auth/dev-login` is now refused (route not registered, with a
startup warning) when `NODE_ENV=production` — it is a Sprint-1
password-less convenience with no credential store behind it, not
something that should ever be reachable in production. Its token's
tenant comes solely from the seeded user record; the endpoint no
longer accepts a client-supplied `tenantId`.

`buildAuthHook` also gained an optional `onAuthFailure` callback (wired
to security-service's `authFailureTotal` counter) and now always
`logger.warn({ reason, path })`s a rejection — the token itself is
never logged.

## Consequences

- Every service now has a hard security boundary at the HTTP edge
  instead of trusting client input for tenant scoping — the header
  spoofing hole this ADR closes.
- Dev/test ergonomics are unchanged by default (`AUTH_DEV_BYPASS`
  defaults true outside production); docker-compose and any CI run
  against `NODE_ENV=production` exercise the real path.
- RS256/JWKS, refresh-token revocation lists beyond the in-memory
  Sprint-1 store, and a real credential-based `/v1/auth/login` remain
  future work — none of them are blocked by this ADR's shape.
- Deferred: `security-service`'s `requireTenantMatch` (comparison-only
  header read) could be dropped once every client stops sending
  `x-tenant-id` at all; `frontend/src/lib/api.ts`'s legacy tenant-header
  fallback (pre-login only, never after a session-expiry 401 — see the
  S6-2 follow-up above) goes away once the login gate is the only path
  into the app; integration-service's webhook ingestion still trusts a
  provider-signed payload's `tenantId` (verified by webhook signature,
  not a bearer token) — a different, still-open trust model.
