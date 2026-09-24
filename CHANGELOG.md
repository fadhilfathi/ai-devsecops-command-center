# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Repository**: <https://github.com/fadhilfathi/ai-devsecops-command-center>

> :construction: **Pre-alpha**: the public API is not stable. The first
> 0.1.0 release will be tagged when the Sprint 1 milestone is complete.

## [Unreleased]

## [0.4.0] - 2026-09-24

Sprint 7 — hardening: lint, dependencies, CI, HTTP security, end-to-end
smoke.

### Added

- **S7-5**: end-to-end smoke of the real docker-compose stack.
  `scripts/e2e-smoke.mjs` mints its own HS256 access token, waits for
  every service's (and the frontend's) `/healthz`, hits one
  authenticated route per service, `/readyz` on the Postgres/Redis-
  backed services, two negative-auth cases, and the nginx `/api/*`
  proxy. `.github/workflows/e2e.yml` runs it against a freshly built
  stack on every push to `main` and weekly (`workflow_dispatch` too).
  The observability toolchain (Prometheus, Alertmanager, Grafana,
  Loki, OTel collector) moved behind a compose `observability` profile
  since it isn't needed to run or smoke the app — see
  `infra/README.md`.

### Changed

- **S7-2**: upgraded Fastify 4→5 across all 13 backend services plus
  `@aicc/shared`/`@aicc/observability` (custom logger now passed as
  `loggerInstance`, `setErrorHandler<FastifyError>` for the now-`unknown`
  default error type), and the matching plugin majors
  (`@fastify/cors` 11, `@fastify/helmet` 13, `@fastify/sensible` 6,
  `@fastify/swagger` 9, `@fastify/swagger-ui` 6, `@fastify/rate-limit` 11,
  `pino` 10, `pino-pretty` 13). Bumped `vitest`/`@vitest/coverage-v8` 2→4
  and `vite`/`@vitejs/plugin-react` 5→7/4→5 in the frontend (vitest 4
  requires vite ^6). Bumped `react-router-dom` 6→7 in the frontend
  (declarative mode, no other API changes needed). Bumped `pyjwt` to
  2.13.0 in `vuln-intel` and `pytest` to 9 in `dependency-intel`.
  Consolidated `.github/dependabot.yml` to a single root npm entry
  (pnpm-workspace-aware) instead of 8 overlapping npm entries, and added
  grouped `pip` entries for the 3 Python security agents. `pnpm audit`:
  0 critical / 0 high / 0 moderate / 0 low (was 2/5/13/1). See
  [ADR 0017](./docs/adr/0017-fastify-5.md).

### Fixed

- **S7-1**: cleared all 45 outstanding ESLint warnings
  (`@typescript-eslint/no-unused-vars`, `@typescript-eslint/no-explicit-any`,
  unused `eslint-disable` directives) at the root — deleted dead
  imports/functions, replaced `any` with real types, and typed a
  `MappingInput` construction in `evidence-attacher.ts` directly instead
  of casting. Along the way, fixed a real bug in
  `inventory-service`'s `/v1/inventory/graph/asset` route, which was
  assigning the internal `AssetKind` (e.g. `'deployment'`) straight to a
  `TopologyNode`'s `kind` field instead of going through the existing
  `toNodeKind()` mapper, producing invalid node kinds in the asset graph.
  `pnpm lint` now runs with `--max-warnings 0` so new warnings fail CI.
- the first real docker-compose run of the S7-5 e2e smoke exposed
  several boot bugs Windows/unit-test development had hidden:
  - every service decided whether to start by comparing
    `import.meta.url` against `file://` + `argv[1]`, which only matches
    Windows paths, so every service exited immediately on Linux; now
    compares against `pathToFileURL(argv[1])`.
  - `@aicc/shared` was missing `"type": "module"`, so it compiled to
    CommonJS and its ESM named exports failed to resolve at runtime.
  - auth- and security-service validated `EVENT_BUS_DRIVER` against a
    stale local enum (`memory`/`nats`/`redis-streams`) and rejected the
    `redis` value the shared `createEventBus()` factory expects,
    crash-looping in compose.
  - cost-intelligence's and topology's HTTP kubernetes-service
    inventory provider only sent `x-tenant-id`, no `Authorization`
    header, so the cross-service call 401'd whenever
    `AUTH_DEV_BYPASS=false` — the compose default. Both now mint a
    short-lived internal service token per request using the shared
    HS256 secret.
  - the frontend healthcheck fetched `localhost`, which resolves to
    `::1`, while the generated nginx config listens on IPv4 only; now
    probes `127.0.0.1`.
  - `.env.example` set `NODE_ENV=development`, overriding the image
    default and skipping the production-only checks (signing-secret
    strength, credential keyring requirement, dev-login disabled); the
    e2e workflow now runs the stack with `NODE_ENV=production`.

### Security

- **S7-4**: CORS allow-list, strict API CSP, body + rate limits on all
  13 services. Added `registerSecurityPlugins` to `@aicc/shared/http`,
  replacing every service's hand-rolled `cors({ origin: true,
credentials: true })` (reflects any origin with credentials) /
  `helmet({ contentSecurityPolicy: false })` block: no CORS by default
  (`CORS_ORIGINS` opt-in allow-list — the SPA is same-origin via
  `/api/*` already), `default-src 'none'` CSP (relaxed only for
  security-service's `/docs`), a `bodyLimit` from `BODY_LIMIT_BYTES`
  (default 1 MiB, with explicit 10 MiB overrides on SBOM
  ingest/generate/analyze and vulnerability ingest), and a global
  `@fastify/rate-limit` (`RATE_LIMIT_MAX`/`RATE_LIMIT_WINDOW`) keyed by
  verified user id, exempting `/healthz`/`/readyz`/`/metrics`, with a
  tighter 10/min limit on auth-service's login/refresh. `trustProxy`
  is now an IP/CIDR allow-list (`TRUST_PROXY_CIDR`) instead of `true` —
  Fastify 5 removed hop-count trust as spoofable. See
  [ADR 0018](docs/adr/0018-http-hardening.md).
- **S7-3**: fixed the 4 GitHub Actions workflows (`sbom`, `security`,
  `scorecard`, `codeql`) that had failed on every push to `main` for
  weeks; pinned every third-party action to a commit SHA; applied
  least-privilege `permissions:` and `persist-credentials: false`
  across all workflows; rewrote `SECURITY.md` to remove fictional
  teams/SLAs/PGP references and describe only real automation; added
  `docs/operations/branch-protection.md`. Follow-up: replaced the
  `release` workflow's `standard-version` step (which rewrote
  `CHANGELOG.md` and pushed a bot commit to `main`) with a
  `workflow_dispatch`-only tag-and-publish flow — no commits, hand-write
  the CHANGELOG section yourself; removed `standard-version` and the
  `release`/`release-dry` Make targets accordingly. Added a
  `github/codeql-action/upload-sarif` step to `scorecard.yml`. Deleted
  the stale `docs/runbooks/security-automation.md` runbook and trimmed
  `security/README.md` to just the wire-format schema contracts —
  both described automation (`security.yml`, `security-issue.yml`,
  a `github-bridge` service) that never existed; fixed the remaining
  references to it in `docs/architecture/event-bus.md` and elsewhere.
  Also part of S7-2: `pnpm audit` 0 critical / 0 high (was 2/5) —
  Dependabot consolidated.

## [0.3.0] - 2026-09-23

Sprint 6 — frontend integration, authentication, event bus, compliance
automation, credential encryption.

### Added

- **S6-4: runtime + health findings auto-mapped to CIS/NIST** —
  `runtime-security-service` (`POST /v1/runtime-security/scan`) and
  `k8s-health-service` (`GET /v1/health/issues`) now publish
  `runtime.risk.detected` / `cluster.health.issue.detected` (one event
  per finding); a new `compliance-service` listener
  (`src/evidence/infrastructure-listener.ts`) normalizes each finding
  into the existing `control-mapper`'s `MappingInput` (a new
  `subjectKind` discriminator keeps the Sprint 2 vulnerability rules
  unchanged) and reuses `EvidenceAttacher`/`PoamService` to create
  control failures + POA&M items + evidence records, exactly like the
  scan-completed flow. 15 new rules in `mapping-rules.json` cover the 9
  runtime-security rule ids and 8 k8s-health issue kinds against real
  CIS v8 / NIST 800-53 control ids. See
  `docs/adr/0015-infrastructure-compliance-mapping.md` and the updated
  `docs/compliance/compliance-matrix.md`.

- **S6-3: Redis Streams event bus driver** — `@aicc/shared/events` gained
  `RedisStreamsEventBus` (`ioredis`), a durable alternative to the
  Sprint 1 `InMemoryEventBus` behind the same `EventBus` interface: one
  Redis Stream per event type, one consumer group per subscribing
  service (fan-out), at-least-once delivery (a throwing handler leaves
  its message pending rather than acking or dropping it).
  `createEventBus({ driver, redisUrl, serviceName, logger })` picks the
  implementation from `EVENT_BUS_DRIVER` (`memory` default, or `redis`
  plus `REDIS_URL`); every service now does
  `deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName, logger })`
  and closes it on shutdown. `auth-`, `agent-`, `security-`, `incident-`,
  `compliance-`, and `integration-service` (the ones that actually
  publish/subscribe) run with `EVENT_BUS_DRIVER=redis` in
  docker-compose; their `/readyz` now also probes the bus. Deferred:
  dead-letter queue, `XAUTOCLAIM` reclaim of stale pending entries, a
  NATS driver. See `docs/adr/0014-redis-streams-event-bus.md`.

- **S6-1: frontend wired to real service APIs (mock fallback)** — no
  API gateway exists, so each backend service is proxied under its
  own `/api/<name>` prefix (dev: `vite.config.ts`'s `SERVICE_TABLE`;
  prod: mirrored `nginx.conf` `location` blocks pointing at the
  compose service names). `src/lib/api.ts`'s `USE_MOCKS` now reads
  `VITE_USE_MOCKS` (default: mocks on), sends `x-tenant-id` from
  `VITE_TENANT_ID`, and falls back to mock data with a console
  warning on any network error or non-2xx response instead of
  crashing the page. Added `frontend/.env.example` and `pnpm test`
  (vitest) with `src/lib/api.test.ts` covering the mock/live/error
  paths.
- **S6-1 review fixes: resource-based proxy table** — the S6-1 proxy
  map was built from service _names_, not the routes those services
  actually mount (e.g. Kubernetes list routes live under
  `/v1/kubernetes/<resource>`, POA&M is mounted unversioned). Replaced
  it with `frontend/proxy-table.mjs`, a single table of `browser path
-> {port, container, upstream path}` verified against every
  `backend/services/*/src/routes/*.ts`, consumed by both
  `vite.config.ts` (dev proxy) and a new `pnpm --filter ./frontend
gen:nginx` script that generates `nginx.conf` (checked in; a test
  asserts it can't drift from the table). `nginx.conf` now has both an
  exact `location = /api/<res>` and a prefix `location /api/<res>/`
  per resource, fixing routes with no trailing slash (e.g.
  `/api/incidents`). `src/lib/api.ts` accessors were repointed at the
  real flattened paths (`/api/clusters`, `/api/health/...`,
  `/api/controls`, `/api/sboms/:id`, ...); `dashboardKpis()` /
  `eventStream()` now reshape security-service's `/security/dashboard`
  aggregate instead of hitting a non-existent `/dashboard/*` route.
  Endpoints with no backend route at all (`vulnerabilities`, SBOM
  components list, security score/vuln-timeline/risk-heatmap/graph)
  are now hard-coded mock-only (never issue a doomed request) and
  documented in `frontend/README.md`. Added an `apiHealth` store +
  `useApiHealth()` hook: a failed live request now shows a persistent
  "Degraded: showing sample data" banner in `AppShell` instead of
  failing silently. `frontend/Dockerfile` takes `VITE_USE_MOCKS` /
  `VITE_TENANT_ID` as build args; the compose `frontend` service now
  builds with `VITE_USE_MOCKS=false` to exercise the real proxy path.

### Security

- **S6-2: auth end-to-end** — every service used to trust a raw
  `x-tenant-id` header (any caller could impersonate any tenant). Added
  `@aicc/shared/auth` (`signAccessToken`/`verifyAccessToken`, HS256,
  constant-time compare, `exp`/`nbf`/`iss`/`aud`/claim checks) and
  `buildAuthHook()`, a Fastify `onRequest` hook now wired into all 13
  backend services' `buildServer()`; it derives `tenantId`/`userId`/
  `userRole` from a verified `Authorization: Bearer` token instead of a
  client-supplied header. `AUTH_DEV_BYPASS` (on by default outside
  `NODE_ENV=production`) falls back to the legacy header for existing
  dev/test flows when no token is present at all — an invalid token is
  always rejected regardless. `loadServiceConfig()` refuses to boot in
  production with the shared default secret. security-service's
  per-service JWT middleware was replaced by the shared hook; its RBAC
  (`requireRole`/`requireTenantMatch`) stays layered on top.
  auth-service's token service now delegates access-token
  sign/verify to the shared implementation (dev-login remains the only
  login entry point — the user repository is seed-only, no password
  hashes). Frontend: `frontend/src/lib/auth.ts` (`login`/`logout`/
  `useAuth`) wraps `POST /v1/auth/dev-login`, `api.ts` sends
  `Authorization: Bearer` (falling back to the legacy tenant header
  when logged out), and a new `Login` route gates the app when
  `VITE_USE_MOCKS=false`. See `docs/adr/0013-service-to-service-auth.md`.
- **S6-2 follow-up: close the tenant-header spoofing gap** — the S6-2
  auth hook was wired service-wide, but most route handlers in
  incident-, integration-, security-, compliance-, and agent-service
  still read `req.headers['x-tenant-id']`/`['x-user-id']` directly, so a
  valid token for tenant A plus a forged `x-tenant-id: <tenant-B>`
  header still read tenant B's data. Every route now derives tenant/user
  identity exclusively from the hook-verified `req.tenantId`/
  `req.userId`; agent-service also stopped accepting `tenantId` in the
  task-submission request body. `POST /v1/auth/dev-login` is refused
  (route not registered, startup warning logged) when
  `NODE_ENV=production`, and no longer accepts a client-supplied
  `tenantId` — the token's tenant always comes from the seeded user
  record. `loadServiceConfig()` now also refuses a secret shorter than
  32 characters (or empty) in production. `buildAuthHook` gained an
  optional `onAuthFailure` counter hook (wired for security-service) and
  always `logger.warn({ reason, path })`s a rejection, never the token.
  `frontend/src/lib/api.ts` stops retrying the legacy `x-tenant-id`
  fallback after a 401 (`sessionExpired()` sets a flag `useAuth`
  exposes so the app shows the login gate instead of silently 401-ing
  every subsequent call). Added wrong-secret and cross-tenant-header
  regression tests to all 13 services. See
  `docs/adr/0013-service-to-service-auth.md`.
- **S6-5: cluster credentials encrypted at rest** — `kubernetes-service`
  no longer stores onboarded-cluster `token`/`ca_bundle` values in
  plaintext. `@aicc/shared/crypto` adds AES-256-GCM envelope helpers
  (`encryptSecret`/`decryptSecret`/`parseKeyring`/`generateKey`) backed
  by `node:crypto`, keyed off a new `AICC_CREDENTIAL_KEYS` env var
  (`keyId:base64key[,...]`, rotation-friendly — old keys stay
  decryptable). Migration `002_cluster_credential_columns` adds
  `token_enc`/`ca_bundle_enc`/`credential_key_id`; a one-shot
  `migrateCredentials()` re-encrypts any existing plaintext rows on
  boot. Production refuses to start without a valid keyring; dev falls
  back to plaintext with a one-time warning. Also fixed a leak where
  the in-memory repository's `list()`/`findById()`/`create()` returned
  the internal `_credentials` field. See
  `docs/adr/0016-credential-encryption-at-rest.md`.

## [0.2.0] - 2026-09-22

Sprint 5 — live Kubernetes, persistence, observability, containerisation.

### Added

- **S5-0/S5-1: build and test baseline** — monorepo now installs and
  builds cleanly: package manifests for `@aicc/shared`, `@aicc/models`,
  `@aicc/observability`, `workspace:*` deps everywhere, `zod` unified to
  v4, `pnpm-lock.yaml` committed. Added `vitest` (+
  `@vitest/coverage-v8`) as a root devDependency; every backend
  service's `"test"` script now runs `vitest run --passWithNoTests`.
  Added `src/app.test.ts` to all 13 services (health route + one
  domain route each, including tenant-header enforcement), plus tests
  for `@aicc/shared` (`loadServiceConfig`, `InMemoryEventBus`) and
  `@aicc/models` (Zod schema parsing) and rewrote the stale
  `compliance-service` control-mapper/poam tests. Baseline: **198
  tests**, all green (`pnpm -r test`); CI's test matrix covers all 13
  services + `backend/models` with `--if-present`.
- **S5-2: live Kubernetes provider** — `LiveProvider`
  (`backend/services/kubernetes/src/providers/live.provider.ts`) wired
  to `@kubernetes/client-node`: one cached client set per cluster,
  `testConnection` via `VersionApi.getCode()`, `list*` calls mapped
  through pure, schema-validated mappers (`k8s-mappers.ts`).
  `ClusterRepository` gained `getConnection()`;
  `getProviderIdForCluster()` now routes onboarded clusters to `live`
  based on their actual `ClusterProvider`. Default provider stays
  `fixture` (`AICC_K8S_PROVIDER`). See
  `docs/adr/0009-live-kubernetes-provider.md`.
- **S5-3: Postgres persistence** — `@aicc/shared/db`: a minimal
  `Queryable` interface, `createPool()`, and a hand-rolled `migrate()`
  (tracks applied migrations in `schema_migrations`, one transaction
  each) — no ORM. `kubernetes-service` gained
  `buildPgClusterRepository()`; `incident-service` gained
  `buildPgIncidentRepository()`, `buildPgRunbookRepository()`, and
  `buildPgChainRepository()`; all select Postgres when `DATABASE_URL`
  is set, in-memory otherwise. Migrations live as TS modules
  (`src/db/migrations.ts`, ship in `dist/`, no copy step);
  nested/variable-shape data is `jsonb`. Tests run the in-memory and
  Postgres implementations through the same `describe.each` suite
  against `@electric-sql/pglite` (in-process Postgres, no Docker). See
  `docs/adr/0010-postgres-persistence.md`.
- **S5-4: Prometheus `/metrics` on every service** —
  `registerHttpMetrics()` in `@aicc/observability`: a Fastify plugin
  exposing `http_request_duration_seconds` / `http_requests_total`
  (`service`, `method`, `route`, `status_code` labels — `route` is
  always the matched Fastify pattern) plus `GET /metrics`. Wired into
  all 13 backend services right after `helmet`/`cors`/`sensible`;
  `security-service` and `compliance-service` share the plugin's
  `/metrics` route with their existing domain metrics. Split
  `@aicc/observability`'s OTel bootstrap into a `./otel` subpath export.
  Added a `backend-services-compose` Prometheus scrape job.
- **S5-5: network-policy inference + mesh detection** — `NetworkPolicy`
  model (`@aicc/models`, matchLabels-only selectors, ingress/egress
  rules) and optional `mesh` (`istio`/`linkerd`) fields on `Namespace`
  and `Pod`. `kubernetes-service`: `listNetworkPolicies()` on the
  provider interface (fixture + live `NetworkingV1Api`), mesh detection
  in the namespace/pod mappers, `GET /v1/kubernetes/network-policies`.
  `topology-service`: `InventoryClient` gained an HTTP implementation
  (`KUBERNETES_SERVICE_URL`); `inferNetworkPolicy()` annotates
  `routes_to`/`calls`/`selects` edges with `unrestricted` / `allowed` /
  `denied` and tags nodes with their mesh; `TopologyGraph` gained an
  optional `networkPolicySummary`. See
  `docs/adr/0011-network-policy-inference.md`.
- **S5-6: Dockerfiles + compose for all 13 services** — one generic
  multi-stage `backend/Dockerfile` (`ARG SERVICE`) for every
  Node/Fastify backend service (`pnpm deploy --prod /out` into a
  non-root `node:22-alpine` runtime stage); `frontend/Dockerfile` (Vite
  build, `nginx:alpine` runtime with SPA fallback) and
  `frontend/nginx.conf`. `docker-compose.yml` builds and wires all 13
  backend services plus the frontend, Postgres (`aicc`/`aicc`/`aicc`,
  one database per service), Grafana moved to host port `3011`. CI's
  Docker job matrix covers all 13 services + frontend.
- **S5-7: cost utilisation from Prometheus** — `UtilisationSource`
  abstraction in `cost-intelligence`:
  `buildSyntheticUtilisationSource()` (unchanged Sprint 4 behaviour) and
  `buildPrometheusUtilisationSource()`, which queries kubelet/cAdvisor's
  `container_cpu_usage_seconds_total` /
  `container_memory_working_set_bytes` via `quantile_over_time`, one
  query per metric/quantile per namespace. Selected via
  `PROMETHEUS_URL`; degrades to synthetic on any failure or missing
  series. Added an HTTP `KubernetesProvider` for `cost-intelligence`
  (`KUBERNETES_SERVICE_URL`). `CostAnalysis.utilisationSource`
  (`'prometheus' | 'synthetic'`) surfaces which source produced the
  estimates. See `docs/adr/0012-cost-utilisation-from-prometheus.md`.
- **S5-8: multi-page PDF reports (pdfkit)** — replaced the hand-rolled
  single-page PDF writer in `reporting-service` with `pdfkit`: running
  header/footer with page numbers (`Page N of M`), tables with wrapped
  cells, zebra striping, and repeated header rows across page breaks,
  and a vector bar-chart helper for report kinds with an obvious
  numeric series (severity counts, cost by namespace, node
  distribution). `Report` gained an optional `charts` field populated
  by the report engine.

### Changed

- Makefile: added `dev-*` targets for the 7 Sprint-4/5 services,
  dropped `db-migrate`/`db-rollback`/`db-seed` (no
  `@aicc/db-migrations` package — every service runs its own
  migrations at startup).
- Deleted the stale `infra/docker/docker-compose.yml` duplicate (never
  wired to the current `backend/services/*` layout; the root
  `docker-compose.yml` has always been the documented local stack).

### Fixed

- Compile and logic errors surfaced by the first real build: Fastify
  v4 `logger` option, missing `return` in route handlers, duplicate
  model exports, k8s-health pods-per-workload lookup, runtime-security
  hostPath severity override, `useFetch` signature, `date-fns`
  dependency, dead `frontend/src/routes.tsx`. Rewrote
  `compliance-service`'s entrypoint to the shared `buildServer()`
  pattern used by every other service. CI: fixed workspace paths and
  the dependency-aware contracts build filter; lint/format/typecheck
  green on Node 22.
- Two latent security-service bugs surfaced by actually booting
  `buildServer()` in tests: `@aicc/models` `toJSONSchema()` now targets
  `draft-07` (fastify's bundled ajv doesn't know the `draft-2020-12`
  meta-schema), and `/sbom/generate`/`/sbom/analyze` drop their
  `response` schema (the recursive `SbomComponentSchema` blew
  fast-json-stringify's call stack) — the payload is still validated
  via `SbomServiceResponseSchema.safeParse` before the event is
  emitted.
- `.github/workflows/ci.yml` Docker job: fixed the missing `REGISTRY`
  env var and hardcoded image path so pushes go to
  `ghcr.io/<repo>/<service>` (push itself stays disabled).

## [Unreleased]

### Added

- **Repository skeleton** (Sprint 1)
  - Monorepo layout with `pnpm` workspaces (`frontend`,
    `backend/services/*`, `backend/packages/*`, `backend/common/*`).
  - Full directory tree: `docs/`, `frontend/`, `backend/`, `agents/`,
    `infra/`, `scripts/`, `tests/`, `.github/`.
  - Root configuration: `package.json`, `pnpm-workspace.yaml`,
    `tsconfig.base.json`, `.editorconfig`, `.gitattributes`,
    `.gitignore`, `.dockerignore`, `.nvmrc`, `.env.example`.
  - Apache-2.0 `LICENSE` and `NOTICE` placeholder.
  - `docker-compose.yml` for the full local stack (Postgres, Redis,
    six services, frontend, Prometheus, Grafana, Loki, OTel collector).
  - `Makefile` with `up` / `down` / `logs` / `test` / `db-*` /
    `release*` / `clean` targets.
  - GitHub workflows: `ci`, `release`, `codeql`, `sbom`, `scorecard`,
    `labeler`.
  - GitHub repo hygiene: `CODEOWNERS`, `dependabot.yml`,
    `PULL_REQUEST_TEMPLATE.md`, issue templates (bug, feature,
    security), `labeler.yml`.
- **Documentation** (Sprint 1)
  - Top-level: this `CHANGELOG.md`, `README.md`, `PROJECT_DESCRIPTION.md`.
  - `CONTRIBUTING.md` with the full dev workflow, coding standards,
    and testing requirements.
  - `SECURITY.md` with the coordinated disclosure process and
    hardening baseline.
  - `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
  - `docs/architecture/`: `README.md`, `system-architecture.md`,
    `agent-topology.md`, `event-bus.md`, `security-model.md`
    (all Sprint 1 drafts; canonical versions coming from
    PlatformArchitect / SecurityArchitect).
  - `docs/agents/README.md`, `docs/compliance/README.md`,
    `docs/security/README.md`, `docs/runbooks/README.md`,
    `docs/operations/README.md`.
  - `docs/adr/`: 0001–0004 by PlatformArchitect (event-bus transport,
    agent comm, event schemas, six-services-one-DB) and 0005–0007 by
    GitOpsManager (record ADRs, monorepo with pnpm, Docker Compose dev).
- **Service scaffolds** (placeholders for Sprint 1 implementation)
  - README for each of the six backend services: `auth`, `agent`,
    `security`, `incident`, `compliance`, `integration`.
  - README for `backend/packages/shared/`.
  - README for `frontend/` describing the eight screens and
    frontend architecture.
  - READMEs for `agents/core/`, `agents/roles/`, `agents/skills/`.
- **Observability config** (root scaffolding; SREEngineer published the
  authoritative `infra/observability/{prometheus,otel-collector,alertmanager,grafana,logs}/`
  tree — see `/docs/observability/`)
  - `infra/observability/README.md` as the entry point.
  - Initial Prometheus, OTel, Loki, Grafana config drafts (SREEngineer
    published the canonical versions).

### Changed

- (none yet — first release)

### Deprecated

- (none yet — first release)

### Removed

- (none yet — first release)

### Fixed

- (none yet — first release)

### Security

- Documented coordinated disclosure process in `SECURITY.md`.
- Documented the security model (RBAC, multi-tenant isolation, audit
  log, agent safety) in `docs/architecture/security-model.md`.
- Pinned Dependabot to weekly updates with group rules per package.

## Sprint 4 — Kubernetes & Infrastructure Intelligence (2026-06-16)

### Added

- **Infrastructure model layer** (`backend/models/infrastructure/`)
  - `cluster.model` — Kubernetes cluster inventory (provider,
    nodes, capacity, connection-test shape).
  - `namespace.model` — namespace inventory with aggregated
    pod / workload / service / restart counters.
  - `workload.model` — abstract workload (Deployment,
    StatefulSet, DaemonSet, ReplicaSet, CronJob, Job, Pod).
  - `pod.model` — pod inventory with container list, last
    termination reason (CrashLoopBackOff, OOMKilled, ...),
    privileged / root / capabilities signals.
  - `service.model` — Service inventory (type, ports, FQDN,
    endpoints, ingress linkage).
  - `deployment.model` — deployment-specific (strategy,
    currentReplicaSet, rollout status, change-cause).
  - `statefulset.model` — StatefulSet-specific (serviceName,
    podManagementPolicy, volumeClaimTemplates).
  - `daemonset.model` — DaemonSet-specific (desired / ready /
    misscheduled counters).
  - `ingres.model` — Ingress inventory (class, rules, TLS).
  - `runtime-risk.model` — runtime-security finding + rollup
    report shape.
  - `topology.model` — node / edge model for the unified
    topology graph.
  - `infrastructure-health.model` — health score (0..100 +
    A..F band) + issues + recommendations.
  - `cost-analysis.model` — per-workload cost + finding +
    recommendation shape.

- **`kubernetes-service`** (S4-EPIC-1, port 4006) — read-only
  K8s inventory across the tenant's onboarded clusters.
  - Endpoints: `/v1/kubernetes/{clusters,namespaces,workloads,
pods,services,ingresses,deployments,statefulsets,
daemonsets}` + `POST /v1/kubernetes/test-connection` +
    `/v1/kubernetes/providers`.
  - Provider abstraction: `fixture` (deterministic in-process
    data) and `live` (placeholder for Sprint 5).
  - Tenant-scoped cluster repository.

- **`k8s-health-service`** (S4-EPIC-2, port 4007) — health
  scoring + detection rules.
  - Detects: CrashLoopBackOff, ImagePullBackOff, OOMKilled,
    Pending, Failed, restart storms, node pressure,
    unschedulable workloads.
  - Score = `100 - 8*critical - 4*high - 2*medium - 1*low`,
    band A..F.
  - Endpoints: `/v1/health/{clusters,namespaces,workloads,
pods,clusters/:id,issues,recommendations}`.

- **`runtime-security-service`** (S4-EPIC-3, port 4008) —
  runtime-risk detection + report generation.
  - 9 rules: AICC-RT-001..009 (privileged, hostPath, root,
    dangerous capability, weak SecurityContext, ServiceAccount
    risk, RBAC risk stub, missing limits, unpinned image).
  - Endpoints: `/v1/runtime-security/{rules,risks,risks/:id,
scan,report,report/cluster/:id}`.

- **`inventory-service`** (S4-EPIC-4, port 4009) — unified
  asset catalog + relationship / dependency graphs.
  - Endpoints: `/v1/inventory/{assets,assets/:id,clusters,
namespaces,services,deployments,graph/asset,
graph/relationships,graph/dependencies,
graph/dependencies/:assetId}`.

- **`cost-intelligence-service`** (S4-EPIC-5, port 4010) —
  resource waste, over-provisioning, under-utilization, cost
  optimisation recommendations.
  - Endpoints: `/v1/cost/{analysis,analysis/cluster/:id,
workloads,findings,recommendations}`.
  - Configurable USD/hour pricing via
    `AICC_COST_CPU_USD_PER_HOUR` /
    `AICC_COST_MEMORY_USD_PER_HOUR`.

- **`topology-service`** (S4-EPIC-6, port 4011) — Service Map,
  Application Graph, Topology Graph, per-namespace view,
  namespace relationships.
  - Endpoints: `/v1/topology/{graphs,service-map,
application-graph,graph,namespace/:name,
namespace-relationships}`.

- **`reporting-service`** (S4-EPIC-10, port 4012) — six
  canonical reports × {json, md, pdf}.
  - Reports: Cluster Health, Infrastructure Risk, Runtime
    Security, Cost Optimization, Topology, Executive Summary.
  - Endpoints: `/v1/reports/...` per report kind.

- **AI incident correlation engine extension** (S4-EPIC-7)
  - New correlation engine in
    `backend/services/incident/src/correlation/`.
  - Subscribes to security / SBOM / CI/CD / K8s /
    infrastructure / deployment / runtime / health event
    topics.
  - Produces `IncidentChain` (root → leaf) + `CorrelationEdge`
    list.
  - New endpoints: `/v1/incidents/chains`,
    `/v1/incidents/chains/:id`, `/v1/incidents/chains/edges/all`.

- **AionUi infrastructure dashboard** (S4-EPIC-8) — 9 new
  pages under `/infrastructure/...`:
  - Infrastructure Overview
  - Cluster Explorer
  - Namespace Explorer
  - Workload Explorer
  - Runtime Security
  - Topology Viewer
  - Cost Intelligence
  - Infrastructure Health
  - Infrastructure Incidents
  - Sidebar gains a new "Infrastructure" section.
  - `types/infrastructure.ts`, `lib/infrastructure.mock.ts`,
    and 20+ new API accessors in `lib/api.ts`.

- **Documentation** (Sprint 4)
  - `docs/kubernetes/` — Kubernetes service overview.
  - `docs/infrastructure/` — design notes for the inventory
    layer.
  - `docs/runtime-security/` — rule set + report shape.
  - `docs/topology/` — graph views and edge semantics.
  - `docs/cost-optimization/` — pricing model + finding
    taxonomy.
  - `docs/architecture/sprint-4/` — architecture notes for
    the Sprint 4 workstream.
  - `ROADMAP.md` (new) — sprint-by-sprint plan.

### Changed

- `components/ui/KpiTile.tsx` now supports both `{ kpi }` and
  inline `{ label, value, hint }` shapes.
- `lib/format.ts` gains `fmtNumber`, `fmtUsd`, `fmtBytes`,
  `fmtCpu` helpers.
- `incident-service` index wires the chain repository + the
  correlation listener.

### Sprint roadmap (planned)

| Sprint | Focus                                                       |
| ------ | ----------------------------------------------------------- |
| 1      | Repo, architecture, documentation, service skeletons        |
| 2      | Auth service: users, tenants, JWT, RBAC                     |
| 3      | Agent runtime: dispatcher, memory, contract registry        |
| 4      | **Security service: assets, SBOM, vulnerabilities** ✅      |
| 4      | **Infrastructure Intelligence** (Sprint 4 workstream) ✅    |
| 5      | Live Kubernetes + Postgres persistence + Prometheus         |
| 6      | Compliance service: control mapping, evidence, attestations |
| 7      | Integration service: GitHub App, webhooks, outbound         |
| 8      | Frontend: Dashboard, Assets, Incidents                      |
| 9      | Frontend: Vulnerabilities, SBOM, Compliance                 |
| 10     | End-to-end workflows, observability, SRE playbooks          |
| 11     | Hardening, security review, OpenSSF Scorecard pass          |
| 12     | 0.1.0 release, public docs, demo data                       |

## Sprint 2 — Security foundation (2026-06-12)

### Added

- **`vuln-intel` service** (S2.2, port 4008) — CVE ingestion, normalization, and scoring
  - Source adapters: NVD 2.0, GitHub Security Advisories (GHSA), OSV.dev
  - Enrichment: FIRST.org EPSS (exploit likelihood) + CISA KEV (known exploited)
  - CVSS 3.0/3.1/4.0 vector parser + custom base-score calculator (no external CVSS lib)
  - Unified `CveRecord` Pydantic schema (CVE-5.0-aligned) with multi-source merge
  - SBOM↔CVE matcher (semver-aware range matching, confidence scoring)
  - FastAPI surface: `POST /vuln-intel/ingest`, `GET /vuln-intel/cve/{id}`,
    `POST /vuln-intel/cve/lookup`, `POST /vuln-intel/score`,
    `POST /vuln-intel/match`, `GET /vuln-intel/stats`, `POST /vuln-intel/sync/once`
  - Health & telemetry: `/livez`, `/readyz` (deep source probe), `/metrics`
  - Append-only JSONL store with restart-safe index; Prometheus instrumentation;
    OTel-ready; structlog JSON logs; non-root Docker image; multi-tenant
  - **36 unit + integration tests passing** (`pytest`, ASGI in-process)

- **`vuln-intel` S2.8 hardening** (single commit, 46 new tests)
  - **Per-feed JSON-Schema validators** (`validators.py`): NVD CVE 5.0 (envelope + per-item), GHSA, OSV, EPSS, KEV. Range-checked numeric fields (CVSS 0–10, EPSS 0–1), severity enum whitelist, port of the AJV schemas from § 3.5. Validators run on every record yielded by the source layer; rejections increment `vuln_intel_validation_rejected_total{source,reason}` and are surfaced in the per-feed audit log.
  - **Safe JSON parsing**: hard `max_depth=20` enforcement, `defusedxml.ElementTree` available for upstream XML feeds. No coerce-on-error — invalid records are rejected, never silently dropped.
  - **Cross-source consensus** (`consensus.py`): HIGH/CRITICAL severity requires corroboration by **≥2 of {NVD, GHSA, OSV}**. Single-source HIGH/CRITICAL is tagged `unofficial` for human review; multi-source gets the `corroborated` tag. Decision class carries `reason ∈ {consensus_ok, single_source_high_critical, below_high}` for metrics/audit labelling.
  - **Per-feed audit log** (`audit.py`): append-only JSONL with file-size-based rotation, thread-safe writes. Every ingest run emits one event: `feed, fetched_at, record_count, accepted_count, rejected_count, signature_valid, validator_version, tenant_id, ingest_run_id, rejected_reasons`. Exposed at `GET /vuln-intel/audit`.
  - **Opt-in LLM exploit scoring** (`llm.py`): `VULN_INTEL_LLM_ENABLED` gate; per-tenant and global token budgets with reservation + refund; OpenAI-compatible `/chat/completions` HTTP client; offline `FakeLlmClient` for tests. Strict `LLM_RESPONSE_SCHEMA` (with `additionalProperties: false`); transport / schema / budget-violation errors all fall back to EPSS. Every call emits an `LlmCallAudit` event. Hooked into the `/vuln-intel/score` flow when `use_llm=true` is passed; default is off.
  - **New metrics** (Prometheus):
    - `vuln_feed_last_refresh_timestamp_seconds{source}` (S2.7 lag-SLO gauge)
    - `vuln_intel_validation_rejected_total{source,reason}`
    - `vuln_intel_consensus_unofficial_total`
    - `vuln_intel_llm_calls_total{status}` (ok / schema_violation / budget_exceeded / transport_error / disabled)
    - `vuln_intel_llm_tokens_total{tenant,kind}`
    - `vuln_intel_llm_budget_remaining{tenant}`
  - **New endpoints**: `GET /vuln-intel/audit`, `GET /vuln-intel/llm/status`
  - **New env vars** (all in `config.py`): `VULN_INTEL_INGEST_SCHEDULE_NVD|GHSA|OSV|EPSS|KEV_MINUTES`, `VULN_INTEL_LLM_*` (model, base_url, api_key, timeout_seconds, max_retries, tenant_budget_tokens, global_budget_tokens, cost_per_1k_micros), `VULN_INTEL_AUDIT_LOG_FILENAME`, `VULN_INTEL_AUDIT_LOG_MAX_BYTES`, `VULN_INTEL_CONSENSUS_MIN_SOURCES_HIGH_CRITICAL`, `VULN_INTEL_FEED_SIGNATURE_REQUIRED`, `VULN_INTEL_VALIDATION_MAX_JSON_DEPTH`
  - **Test coverage** (`test_validators.py`, `test_consensus.py`, `test_audit.py`, `test_llm.py`): 46 new tests covering CF-01..CF-07 (feed validation + consensus) and LP-01..LP-09 (LLM scoring). Full suite **82/82 passing**.

- **`vuln-intel` S2.8 follow-up** (2026-06-12, post-Sprint-2-closeout, 7 new tests)
  - **Metric rename**: `vuln_feed_last_refresh_timestamp_seconds` → `devsecops_vuln_feed_last_refresh_timestamp_seconds` with **required `service` and `source` labels** (SREEngineer spec §3.11).
  - **`affected[].introduced` → `introduced_in` rename** + new `introduced_at` field. The two fields are intentionally separate (per FullstackEngineer Pydantic↔Zod alignment, 2026-06-12): `introduced_in` is per-version semver (on the wire), `introduced_at` is per-deploy ISO-8601 (internal-only, security-service projection strips it).
  - **`CveRecord.consensus_sources: list[str]`** — populated by the consensus pass after every ingest run, emitted to the GitOps wire (O-3.7 19-field schema). Used by security-service :4003 for the `length(consensus_sources) >= 2` condition of the 4-condition `auto_actionable` gate.
  - **`CveRecord.vuln_intel_pre_actionable: bool | None`** — internal pre-actionable hint (NEVER on the wire). Computed by `Service._compute_pre_actionable()`: `(kev OR (high/critical AND epss >= 0.36)) AND fix_available`. The wire `auto_actionable` is computed by security-service as the 4-condition AND.
  - **LLM audit additions**: `clamp_applied` + `human_review_routed` fields on `LlmCallAudit` (SecurityArchitect S2.8 §T-03 detection signal). The clamp band is `[EPSS - cvss_width, EPSS + cvss_width]` where `cvss_width = (cvss_base / 10) * 0.3`. When the LLM score is outside the band, both flags are set to True.
  - **Threat-model citations**: `validators.py` and `consensus.py` docstrings cite `docs/architecture/s2-security-mitigations.md` § 3.5 (per-feed JSON-Schema validation, T-02 CVE feed poisoning) and § 3.6 (flag-don't-downgrade policy, O-3.6 4-condition `auto_actionable` gate).
  - **Test coverage** (7 new tests): 2 in `test_models.py` (consensus_sources default, pre_actionable default), 2 in `test_models.py` (introduced_in rename, introduced_at field), 3 in `test_llm.py` (clamp-outside-band → human_review, clamp-inside-band → no human_review, clamp_band helper). Full suite **89/89 passing**.

- **`vuln-intel` S2.8 finalization** (2026-06-12, post-Sprint-2-closeout)
  - **Post-parse sanity check demoted** per SecurityArchitect recommendation (Q2 reply, 2026-06-12). The per-record sanity check in `Service.ingest()` was duplicating work already done by the source-layer `validate_record()` call — the source layer is the source of truth. Removed the redundant `source_validator.validate_record(_synthesize_raw(rec, src.value))` call from the ingest loop and deleted the `_synthesize_raw()` helper. Kept `_accepted_result()` to emit per-record audit log placeholders. The metric-promotion + hard-reject path SecurityArchitect asked about is no longer applicable: if source-layer validation passes and the sanity check disagrees, that's a code bug to fix, not a runtime decision. No new metrics, no new SRE alerts from this. Full suite still **89/89 passing** after the demotion.

- **`dependency-intel` service** (S2.3, port 4009) — dependency graph + risk
  - CycloneDX/SPDX-compatible SBOM ingest (per-component + per-dependency)
  - Graph builder with PURL-keyed nodes, dedupe across SBOMs, workspace merge
  - Pure-Python personalised PageRank on the **reversed** graph for risk
    propagation from vulnerable leaves up to roots
  - Risk formula: `risk_i = alpha * (0.4 * local_i + 0.6 * pr_i) + (1 - alpha) * baseline`
  - Vulnerability cluster detection (CVE-shared-neighbour groups)
  - GraphML / DOT / JSON export for the UI
  - FastAPI surface: `POST /dep-intel/graph/build`, `GET /dep-intel/graph/{id}`,
    `POST /dep-intel/graph/{id}/correlate`, `POST /dep-intel/risk/calculate`,
    `GET /dep-intel/risk/{id}`, `GET /dep-intel/clusters/{id}`,
    `GET /dep-intel/graph/{id}/export`
  - Talks to `vuln-intel` via the documented S2.5 contract
  - **24 unit + integration tests passing**

- **Smoke tests** in `scripts/`:
  - `smoke_vuln_intel.py` — pure-Python CVSS, model, matcher smoke
  - `smoke_e2e_security.py` — in-process end-to-end (ingest → match → risk)
  - `smoke_boot_services.py` — boots both HTTP services in subprocesses and
    verifies `/livez`, `/metrics`, and OpenAPI paths
  - `verify_compile.py` — bytecode-compile gate

### Changed

- Service skeletons from Sprint 1 now have full implementations in Python
  (vuln-intel, dependency-intel) co-located under
  `agents/roles/security/{vuln-intel,dependency-intel}/`.

## Sprint roadmap (planned)

| Sprint | Focus                                                       |
| ------ | ----------------------------------------------------------- |
| 1      | Repo, architecture, documentation, service skeletons        |
| 2      | Auth service: users, tenants, JWT, RBAC                     |
| 3      | Agent runtime: dispatcher, memory, contract registry        |
| 4      | Security service: assets, SBOM, vulnerabilities             |
| 5      | Incident service: lifecycle, correlation, playbooks         |
| 6      | Compliance service: control mapping, evidence, attestations |
| 7      | Integration service: GitHub App, webhooks, outbound         |
| 8      | Frontend: Dashboard, Assets, Incidents                      |
| 9      | Frontend: Vulnerabilities, SBOM, Compliance                 |
| 10     | End-to-end workflows, observability, SRE playbooks          |
| 11     | Hardening, security review, OpenSSF Scorecard pass          |
| 12     | 0.1.0 release, public docs, demo data                       |

## Security changelog

> **Status:** Auto-managed by
> [`.github/workflows/security.yml`](.github/workflows/security.yml)
> (owner: GitOpsManager). Do not hand-edit — the bot will
> overwrite any changes inside the markers.

This section is a **pointer** to the canonical, auto-generated
security changelog. It is intentionally lightweight here so
humans don't merge in 200 lines of raw CVE noise every release.
The real data lives under [`security/`](security/) and is
updated continuously by CI.

### Where to look

| What                                  | Where                                                                                         |
| ------------------------------------- | --------------------------------------------------------------------------------------------- |
| Daily vulnerability findings (NDJSON) | [`security/vulns/<YYYY-MM-DD>.json`](security/vulns/) (90-day retention)                      |
| Weekly digest (Markdown)              | [`security/vulns/weekly-<YYYY-Www>.md`](security/vulns/) (kept indefinitely)                  |
| SBOM artifacts                        | [`security/sboms/<sbom_id>/`](security/sboms/) (kept indefinitely; also attached to Releases) |
| SBOM index                            | [`security/sboms/index.json`](security/sboms/index.json) (NDJSON, one line per SBOM)          |
| Response SLA                          | [`SECURITY.md` → Response targets (SLA)](SECURITY.md#response-targets-sla)                    |
| Coordinated disclosures               | GitHub Security Advisories tab                                                                |
| Disclosed CVEs (post-disclosure)      | `CHANGELOG.md` "Security" section of the corresponding release entry                          |

### Schema & contract

See [`security/README.md`](security/README.md) for the locked
folder + event-payload contracts. See
[`docs/runbooks/security-automation.md`](docs/runbooks/security-automation.md)
for the operator runbook (triage, override, rollback).

<!-- BEGIN:auto:security-pointer -->
<!-- END:auto:security-pointer -->

## Release history

| Version | Date       | Notes                                                                    |
| ------- | ---------- | ------------------------------------------------------------------------ |
| 0.4.0   | 2026-09-24 | Hardening: lint, dependencies, CI, HTTP security, end-to-end smoke       |
| 0.3.0   | 2026-09-23 | Frontend integration, auth, event bus, compliance automation, encryption |
| 0.2.0   | 2026-09-22 | Live Kubernetes, persistence, observability, containerisation            |
| 0.0.0   | 2026-06-12 | Initial repository skeleton                                              |

<!--
## [0.1.0] - YYYY-MM-DD

### Added
- …

### Changed
- …

### Fixed
- …
-->
