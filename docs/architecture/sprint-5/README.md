# Sprint 5 — Architecture Notes

Sprint 5 turns Sprint 4's fixture-only Infrastructure
Intelligence stack into something that can point at a real
cluster and survive a restart: a live `KubernetesProvider`,
Postgres persistence for the state that used to live in
process memory, Prometheus metrics on every service, network
policy / mesh-aware topology, Prometheus-derived cost
utilisation, multi-page PDF reports, and containerisation for
the whole thing.

## Build and test baseline (S5-0, S5-1)

Before any of the feature work, the monorepo didn't reliably
build. S5-0 fixed the workspace wiring (`@aicc/shared`,
`@aicc/models`, `@aicc/observability` as real packages,
`workspace:*` deps, a unified `zod` v4), the compile errors
that build surfaced, and got CI green on lint/format/typecheck.
S5-1 added `vitest` to every workspace (root devDependency,
per-service `test` script) with a health-route + one
domain-route test per service, plus unit tests for
`@aicc/shared` and `@aicc/models`.

Current baseline: **198 tests**, all green, across 13 backend
services + `@aicc/shared` + `@aicc/models`
(`pnpm -r test`). CI runs the same matrix per-workspace on every
push.

## Live Kubernetes provider (S5-2)

`kubernetes-service`'s `LiveProvider` wires
`@kubernetes/client-node`: one client set (`CoreV1Api`,
`AppsV1Api`, `NetworkingV1Api`, `VersionApi`) per cluster,
cached in-process keyed by `tenantId:clusterId` so no client is
ever shared across tenants. `list*` calls map through pure,
`Schema.parse()`-validated functions in `k8s-mappers.ts`. The
provider is selected per cluster by `ClusterRepository`'s
`getProviderIdForCluster()` based on the cluster's own
`ClusterProvider` field; the service-wide default (used when a
cluster hasn't been onboarded with a specific provider) is
`AICC_K8S_PROVIDER` (`fixture` by default). See
[ADR 0009](../../adr/0009-live-kubernetes-provider.md).

## Postgres persistence (S5-3)

Four repositories that were in-memory-only in Sprint 4 can now
back onto Postgres: `ClusterRepository` (kubernetes-service),
`IncidentRepository`, `RunbookRepository`, and `ChainRepository`
(incident-service). `@aicc/shared/db` provides the plumbing — a
minimal `Queryable` interface, `createPool()`, and a hand-rolled
`migrate()` (tracks applied migrations in `schema_migrations`,
one transaction per migration) — no ORM. Migrations are plain
TS modules (`src/db/migrations.ts`) so they ship in `dist/`
with no copy step; nested/variable-shape data is `jsonb`, only
filter/sort keys get real columns.

Each service resolves `DATABASE_URL ? buildPg...() :
buildInMemory...()` at startup — in-memory stays the default
for local dev and CI. Tests run the in-memory and Postgres
implementations through the same `describe.each` suite against
`@electric-sql/pglite` (in-process Postgres, no Docker
required). The correlation buffer that feeds `ChainRepository`
stays in-memory by design — it's a sliding window, not a
source of truth. See
[ADR 0010](../../adr/0010-postgres-persistence.md).

## Prometheus metrics on every service (S5-4)

`@aicc/observability` gained `registerHttpMetrics()`: a Fastify
plugin exposing `http_request_duration_seconds` /
`http_requests_total` (labelled `service`, `method`, `route`,
`status_code` — `route` is always the matched Fastify pattern,
never the raw URL) plus `GET /metrics`. It's wired into all 13
backend services right after `helmet`/`cors`/`sensible`;
`security-service` and `compliance-service` share the plugin's
`/metrics` route with their pre-existing domain metrics instead
of hand-rolling their own. The OTel SDK bootstrap moved to a
`./otel` subpath export so importing `@aicc/observability`'s
root no longer pulls it in. `docker-compose.yml`'s Prometheus
has a `backend-services-compose` job scraping all 13.

## Network-policy inference + mesh detection (S5-5)

`topology-service`'s `inferNetworkPolicy()` annotates
`routes_to`/`calls`/`selects` edges with `unrestricted` /
`allowed` / `denied` based on the cluster's `NetworkPolicy`
objects, and tags nodes with their service mesh (`istio` /
`linkerd`). Scope is deliberately narrow: `matchLabels`
selectors only (no `matchExpressions`), ingress rules only (no
egress evaluation), and mesh detection is a label/sidecar-name
heuristic, not a CRD read. `kubernetes-service` gained
`listNetworkPolicies()` (fixture + live `NetworkingV1Api`) and
`GET /v1/kubernetes/network-policies`; `topology-service`'s
`InventoryClient` gained an HTTP implementation
(`KUBERNETES_SERVICE_URL`) alongside its fixture default. See
[ADR 0011](../../adr/0011-network-policy-inference.md).

## Cost utilisation from Prometheus (S5-7)

Sprint 4's cost engine sized recommendations off fixed
synthetic utilisation ratios. `cost-intelligence-service` now
has a `UtilisationSource` abstraction with two
implementations: `buildSyntheticUtilisationSource()` (the
unchanged Sprint 4 behaviour) and
`buildPrometheusUtilisationSource()`, which queries
kubelet/cAdvisor's `container_cpu_usage_seconds_total` /
`container_memory_working_set_bytes` via `quantile_over_time`,
batched to one query per metric/quantile per namespace.
Selected via `PROMETHEUS_URL`; degrades to synthetic on any
failure, timeout, or missing series so a request never fails
because Prometheus is unreachable.
`CostAnalysis.utilisationSource` (`'prometheus' |
'synthetic'`) reports which source actually produced the
numbers, not just whether the env var is set. `cost-intelligence`
also gained an HTTP `KubernetesProvider`
(`KUBERNETES_SERVICE_URL`), mirroring the topology-service
pattern. See
[ADR 0012](../../adr/0012-cost-utilisation-from-prometheus.md).

## Multi-page PDF reports (S5-8)

`reporting-service` replaced its hand-rolled single-page PDF
writer with `pdfkit`: a running header/footer with page numbers
(`Page N of M`), tables with wrapped cells and zebra striping
that repeat their header row across page breaks, and a vector
bar-chart helper for report kinds with an obvious numeric
series (severity counts, cost by namespace, node distribution).
`Report` gained an optional `charts` field populated by the
report engine.

## Containerisation (S5-6)

One generic multi-stage `backend/Dockerfile` (`ARG SERVICE`)
builds any of the 13 Node/Fastify services: install the whole
workspace, `pnpm --filter "@aicc/<service>-service..." build`,
then `pnpm --filter "@aicc/<service>-service" deploy --prod
/out` for a self-contained production tree copied into a
non-root `node:22-alpine` runtime stage. `frontend/Dockerfile`
builds the Vite SPA and serves it from `nginx:alpine` with SPA
fallback routing. `docker-compose.yml` builds and wires all 13
backend services plus the frontend, Postgres (`aicc`/`aicc`/
`aicc`, one database per service), Redis, Prometheus,
Alertmanager, Grafana (moved to host port `3011` — `3001` is
`auth-service`), Loki, and the OTel collector. CI's Docker job
builds all 13 service images + the frontend (14 total) on every
push; pushing to GHCR is disabled for now.

## How to run it

Default (no env vars) is fully in-memory / fixture-backed — no
external dependencies:

```bash
pnpm install
pnpm --filter @aicc/kubernetes-service dev   # etc., per service
```

or the full containerised stack:

```bash
docker compose up --build
```

| Env var                  | Service(s)                                                                                  | Default (unset)                      | Live behaviour                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------- |
| `AICC_K8S_PROVIDER`      | `kubernetes-service`                                                                        | `fixture`                            | Default provider for clusters without an explicit `ClusterProvider`. |
| `DATABASE_URL`           | `kubernetes-service`, `incident-service`, plus `auth`/`security`/`compliance`/`integration` | unset → in-memory repositories       | Postgres-backed repositories via `@aicc/shared/db`.                  |
| `KUBERNETES_SERVICE_URL` | `k8s-health`, `runtime-security`, `inventory`, `cost-intelligence`, `topology`, `reporting` | unset → in-process fixture inventory | HTTP client against `kubernetes-service`, Zod-validated.             |
| `PROMETHEUS_URL`         | `cost-intelligence-service`                                                                 | unset → synthetic utilisation        | Real kubelet/cAdvisor-derived CPU/memory utilisation.                |

Grafana is at `http://localhost:3011` (`admin`/`admin`) when
running via `docker compose up --build`.

## What is still mocked

- Every inventory-consuming service defaults to the `fixture`
  Kubernetes provider / in-process inventory client; live
  wiring is opt-in via the env vars above.
- The frontend (`frontend/src/lib/*.mock.ts`) still renders
  mock data — it is not wired to any of the real service APIs
  yet (Sprint 6).
- There is no auth wiring between services; every route trusts
  the `x-tenant-id` header as a development shortcut.
- The incident correlation buffer that feeds `ChainRepository`
  is in-memory only (sliding window, not a source of truth —
  see ADR 0010).
- Cluster credentials (`kubernetes-service`'s `clusters` table)
  are stored unencrypted, matching the Sprint 4 in-memory
  behaviour exactly. Encryption at rest is a follow-up (see
  ADR 0010's Consequences).
- CI builds all 13 service images + the frontend but does not
  push them to GHCR.

## Next steps (Sprint 6)

See `ROADMAP.md` — frontend wired to real service APIs, auth
end-to-end, an event-bus driver beyond in-memory, compliance
auto-mapping of runtime risks to CIS/NIST, and credential
encryption at rest.
