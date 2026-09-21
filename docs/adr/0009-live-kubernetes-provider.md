---
status: accepted
date: 2026-09-21
deciders: SREEngineer
---

# 0009 — Live Kubernetes provider

## Context

Sprint 4 shipped the `kubernetes` service with a provider abstraction
(`KubernetesProvider`) behind a deterministic `fixture` provider. The
`live` provider was a stub that threw `UnsupportedError`. Sprint 5
wires it to a real Kubernetes API server.

## Decision

- Use `@kubernetes/client-node` (1.x, OSS, no cost) as the API client.
- `LiveProvider` builds one client set (`CoreV1Api`, `AppsV1Api`,
  `NetworkingV1Api`, `VersionApi`) per cluster via
  `KubeConfig.loadFromClusterAndUser`, then caches it in a plain
  in-process `Map<"tenantId:clusterId", K8sClients>` for the life of the
  process (tenant-scoped key so no client is ever shared across tenants).
  (ponytail: no TTL/eviction — add one if clusters churn at runtime.)
- The client factory is injectable (`clientFactory` constructor option)
  so tests supply fakes instead of hitting a real API server.
- Every `list*` call maps raw `V1*` API objects through pure functions
  in `k8s-mappers.ts`, each ending in `Schema.parse()` so a bad mapping
  fails loudly instead of shipping malformed data to the dashboard.
- Read-only: only `list*` and `getCode` (version) calls are issued.
- `ClusterRepository.getConnection()` returns the stored `server` +
  credentials for a cluster. `getProviderIdForCluster()` routes every
  onboarded cluster to `live` unless its `ClusterProvider` is literally
  `'fixture'` — the enum otherwise enumerates cloud vendors (eks, gke,
  aks, ...), none of which are meaningfully "fixture".
- Cluster credentials remain in-memory only, matching the Sprint 4
  `ClusterRepository` stub. Persistence (encrypted at rest) is
  deferred to Sprint 5-3.

## Consequences

- **Easier**: dashboards can point at a real cluster (e.g. `kind`)
  with zero new infra; the provider interface stays unchanged for
  callers (routes, dashboard, tests).
- **Harder**: no endpoint-derived `Service.hasReadyEndpoints` /
  `endpoints` yet (would need a separate `Endpoints` list call per
  service — add when the topology view needs it). Some Deployment
  fields (`currentReplicaSet`, `previousReplicaSet`) are left `undefined`
  since ReplicaSet lookups aren't wired.

## Alternatives considered

- **kubectl shell-out**: rejected — fragile, no typed responses, extra
  binary dependency.
- **Watch-based caching (informers)**: deferred. The dashboard's poll
  cadence doesn't yet need push updates; add if list-call latency
  becomes a problem.
