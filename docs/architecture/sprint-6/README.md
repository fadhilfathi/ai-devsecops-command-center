# Sprint 6 — Architecture Notes

Sprint 6 turns the fixture/mock-only edges of the platform into
something that actually talks to itself: the frontend hits real
service APIs instead of `src/lib/*.mock.ts`, every backend service
verifies a real JWT instead of trusting a raw tenant header, the
event bus gets a durable driver, infrastructure findings feed
compliance automatically, and cluster credentials are encrypted at
rest.

## Frontend on real APIs (S6-1)

No API gateway exists, so each backend service is proxied under its
own `/api/<resource>` prefix. `frontend/proxy-table.mjs` is the single
source of truth — a table of `browser path -> {port, container,
upstream path}` verified against every `backend/services/*/src/routes/
*.ts` — consumed both by `vite.config.ts` (dev proxy) and
`pnpm --filter ./frontend gen:nginx`, which generates the checked-in
`frontend/nginx.conf` (a test asserts it can't drift from the table).
Each resource gets both an exact `location = /api/<res>` and a prefix
`location /api/<res>/` block, so routes with no trailing slash (e.g.
`/api/incidents`) resolve correctly.

`src/lib/api.ts`'s `USE_MOCKS` reads `VITE_USE_MOCKS` (default: mocks
on); `get<T>()` falls back to mock data with a console warning on any
network error or non-2xx response instead of crashing the page, and
records the failure in an `apiHealth` store — `useApiHealth()` drives a
persistent "Degraded: showing sample data" banner in `AppShell` rather
than failing silently. A handful of accessors
(`api.vulnerabilities()`, `api.sbom()`, `api.securityScore()`,
`api.vulnTimeline()`, `api.riskHeatmap()`, `api.graphData()`) have no
matching backend route at all and are hard-coded mock-only — see
`frontend/README.md`. `frontend/Dockerfile` takes `VITE_USE_MOCKS` /
`VITE_TENANT_ID` as build args (Vite inlines `import.meta.env.VITE_*`
at build time); the compose `frontend` service builds with
`VITE_USE_MOCKS=false` to exercise the real proxy path end to end.

## Auth end-to-end (S6-2)

Every service used to trust a raw `x-tenant-id`/`x-user-id` header —
any caller could impersonate any tenant. `@aicc/shared/auth`
(`signAccessToken`/`verifyAccessToken`, HS256, constant-time compare,
`exp`/`nbf`/`iss`/`aud`/claim checks) and `buildAuthHook()`, a Fastify
`onRequest` hook, are now wired into all 13 backend services'
`buildServer()`; the hook sets `req.tenantId`/`req.userId`/
`req.userRole` from the verified token, never from a client-supplied
header. `AUTH_DEV_BYPASS` (on by default outside `NODE_ENV=production`)
falls back to the legacy header only when no token is present at all —
an invalid token is always rejected regardless of bypass.

The first cut wired the hook but left most route handlers still
reading `req.headers['x-tenant-id']` directly — **a valid token for
tenant A plus a forged `x-tenant-id: <tenant-B>` header still read
tenant B's data.** This closed a real tenant-spoofing hole, not a
theoretical one. The follow-up repointed every route in incident-,
integration-, security-, compliance-, and agent-service at the
hook-verified `req.tenantId`/`req.userId` exclusively; agent-service
also stopped accepting `tenantId` in the task-submission request body.
`POST /v1/auth/dev-login` is refused (route not registered, startup
warning logged) in production and no longer accepts a client-supplied
`tenantId` — the token's tenant always comes from the seeded user
record. `loadServiceConfig()` refuses to boot in production with the
default shared secret, or with a secret shorter than 32 characters.

Frontend: `frontend/src/lib/auth.ts` (`login`/`logout`/`useAuth`) wraps
`POST /v1/auth/dev-login`; `api.ts` sends `Authorization: Bearer`
(falling back to the legacy tenant header only pre-login); a `Login`
route gates the app when `VITE_USE_MOCKS=false`. A session-expiry 401
no longer silently retries the legacy header — it flips a flag
`useAuth` exposes so the app shows the login gate instead. See
[ADR 0013](../../adr/0013-service-to-service-auth.md).

## Redis Streams event bus (S6-3)

`@aicc/shared/events` gained `RedisStreamsEventBus` (`ioredis`)
alongside the Sprint 1 `InMemoryEventBus`, behind the same `EventBus`
interface: one Redis Stream per event type (`aicc:events:<type>`), one
consumer group per subscribing service (fan-out, mirroring the
in-memory `Set<handler>`-per-type semantics), at-least-once delivery —
a throwing handler leaves its message pending (no `XACK`) rather than
acking or dropping it. `createEventBus({ driver, redisUrl, serviceName,
logger })` picks the implementation from `EVENT_BUS_DRIVER` (`memory`
default, or `redis` plus `REDIS_URL`); every service does `deps?.bus ??
createEventBus({ ...cfg.eventBus, serviceName, logger })` and closes it
on shutdown. `auth-`, `agent-`, `security-`, `incident-`,
`compliance-`, and `integration-service` (the ones that actually
publish/subscribe) run with `EVENT_BUS_DRIVER=redis` in
docker-compose; their `/readyz` now also probes the bus.

Caveat: `XADD ... MAXLEN ~ 10000` trims by length, not by pending
state, so a stream that keeps growing while a consumer is down will
eventually evict entries still in that consumer's pending list —
at-least-once holds only while a consumer keeps up with roughly the
last 10k events per type. Deferred: dead-letter queue, `XAUTOCLAIM`
reclaim of a crashed consumer's pending entries, a NATS driver. See
[ADR 0014](../../adr/0014-redis-streams-event-bus.md).

## Compliance auto-mapping of infrastructure findings (S6-4)

`runtime-security-service` (`POST /v1/runtime-security/scan`) and
`k8s-health-service` (`GET /v1/health/issues`) now publish
`runtime.risk.detected` / `cluster.health.issue.detected` (one batched
event per request, `findings[]`, published without awaiting so it
never blocks the response). A new compliance-service listener
(`src/evidence/infrastructure-listener.ts`) normalizes each finding
into the existing `control-mapper`'s `MappingInput` — a new
`subjectKind: 'vulnerability' | 'runtime_risk' | 'health_issue'`
discriminator (default `'vulnerability'`) keeps every Sprint-2
vulnerability rule matching exactly as before, gated behind a new
`subject_kind_is` predicate so infrastructure findings can't leak into
vulnerability-only controls. 16 new rules in `mapping-rules.json` cover
the 9 runtime-security rule ids and the 8 k8s-health issue kinds
against real CIS v8 / NIST 800-53 control ids.

Evidence reuses `EvidenceAttacher` via a new
`attachInfrastructureFinding()` method — same mapping engine, same
`PoamService` dedup, same in-memory blob store, no SBOM/report pair
(the finding JSON itself is the evidence body). Because
`k8s-health-service` republishes every open issue on every
`GET /v1/health/issues` poll, evidence dedups by `(tenantId, controlId,
ref)` — the blob ref is deterministic per finding id, so redelivery
resolves to the same ref and never double-inserts. See
[ADR 0015](../../adr/0015-infrastructure-compliance-mapping.md) and
`docs/compliance/compliance-matrix.md`.

## Cluster credential encryption at rest (S6-5)

`kubernetes-service` no longer stores onboarded-cluster `token`/
`ca_bundle` values in plaintext. `@aicc/shared/crypto` adds AES-256-GCM
envelope helpers (`encryptSecret`/`decryptSecret`/`parseKeyring`/
`generateKey`) on `node:crypto` — no new dependency. Ciphertext format
is `v1.<keyId>.<iv-b64>.<tag-b64>.<ct-b64>`, keyed off
`AICC_CREDENTIAL_KEYS` (`keyId:base64key[,...]`); the first entry is
the active (encrypt) key, every entry stays decryptable — that's the
rotation mechanism.

Migration `002_cluster_credential_columns` adds `token_enc`/
`ca_bundle_enc`/`credential_key_id` alongside the legacy plain columns
(kept for now — dropping them is a later migration). Two one-shot
passes run at startup, only when a keyring is configured:
`migrateCredentials()` re-encrypts any existing plaintext rows onto the
active key, and `reencryptCredentials()` moves any row still under a
non-active (rotated-out) key onto the current active key — this is
what makes rotation safe: the old key only needs to stay in the
keyring until that pass has moved every row off it. Production refuses
to boot without a valid keyring; dev falls back to plaintext with a
one-time logged warning. Also fixed a leak where the in-memory
repository's `list()`/`findById()`/`create()` returned the internal
`_credentials` field. See
[ADR 0016](../../adr/0016-credential-encryption-at-rest.md).

## How to run it

Default (no env vars) is fully in-memory / fixture-backed / mock-backed
— no external dependencies:

```bash
pnpm install
pnpm --filter @aicc/kubernetes-service dev   # etc., per service
cd frontend && pnpm dev                       # mocks on by default
```

or the full containerised stack, which exercises every S6 feature
(real auth, Redis Streams, encrypted credentials, real frontend proxy):

```bash
docker compose up --build
```

| Env var                                                     | Service(s)                                                           | Default (unset)                          | Live behaviour                                                                    |
| ----------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------- |
| `VITE_USE_MOCKS`                                            | `frontend`                                                           | `true`                                   | Renders from `src/lib/*.mock.ts` instead of proxying to real services.            |
| `AUTH_JWT_SECRET` / `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE` | all 13 backend services                                              | dev default secret / `aicc` / `aicc-api` | HS256 sign/verify config; production refuses the default or a secret <32 chars.   |
| `AUTH_DEV_BYPASS`                                           | all 13 backend services                                              | `true` outside production                | Falls back to the legacy `x-tenant-id`/`x-user-id` headers when no token is sent. |
| `EVENT_BUS_DRIVER`                                          | `auth`, `agent`, `security`, `incident`, `compliance`, `integration` | `memory`                                 | `redis` selects `RedisStreamsEventBus` (requires `REDIS_URL`).                    |
| `REDIS_URL`                                                 | same as above                                                        | unset                                    | Redis connection string for the Streams driver.                                   |
| `AICC_CREDENTIAL_KEYS`                                      | `kubernetes-service`                                                 | unset → plaintext (dev warning)          | AES-256-GCM keyring (`keyId:base64key[,...]`); required in production.            |

Also see the Sprint 5 table in
[`../sprint-5/README.md`](../sprint-5/README.md) (`AICC_K8S_PROVIDER`,
`DATABASE_URL`, `KUBERNETES_SERVICE_URL`, `PROMETHEUS_URL`), unchanged
by Sprint 6.

## What is still mocked / deferred

- `frontend`'s `VITE_USE_MOCKS` defaults `true`; even with it `false`,
  `api.vulnerabilities()`, `api.sbom()`, `api.securityScore()`,
  `api.vulnTimeline()`, `api.riskHeatmap()`, and `api.graphData()` are
  hard-coded mock-only — there is no matching backend route yet.
- Every inventory-consuming service still defaults to the `fixture`
  Kubernetes provider / in-process inventory client (unchanged from
  Sprint 5).
- Auth is HS256 with one shared secret across services; RS256/JWKS, a
  refresh-token revocation list beyond the in-memory Sprint-1 store,
  and a real credential-based `/v1/auth/login` are future work.
  integration-service's webhook ingestion still trusts a
  provider-signed payload's `tenantId` (verified by webhook signature,
  not a bearer token) — a separate, still-open trust model.
- No dead-letter queue and no `XAUTOCLAIM` reclaim of a crashed
  consumer's pending Redis Streams entries; trimming (`MAXLEN ~
10000`) doesn't respect pending state; no NATS driver.
- Compliance auto-mapping has no control-scoring weights (every
  matched rule contributes a boolean `'fail'`) and no drift/attestation
  re-check — closing a POA&M item stays a manual/API action.
- Cluster credentials: the legacy plaintext `token`/`ca_bundle` columns
  are still present (dropping them is a later migration); rotation
  requires an operator to run the documented procedure (prepend the new
  key, redeploy, verify the re-encryption count hits zero, then remove
  the old key) — there's no automated rotation schedule; and there is
  no KMS (AWS/GCP KMS, Vault) — the env-var keyring is the zero-cost
  local-first equivalent.
- CI still builds all 13 service images + the frontend but does not
  push them to GHCR (unchanged from Sprint 5).

## Next steps (Sprint 7)

See `ROADMAP.md` — eslint warning cleanup with `--max-warnings 0` in
CI, a dependency/supply-chain pass, the OpenSSF Scorecard hardening
items, rate limiting/request-size limits/security headers audit, and a
real end-to-end docker-compose smoke test.
