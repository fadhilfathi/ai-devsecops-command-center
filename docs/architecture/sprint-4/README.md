# Sprint 4 — Architecture Notes

Sprint 4 transforms the AICC platform from "CI/CD
Intelligence" into "Infrastructure Intelligence". The
platform now understands Kubernetes, infrastructure
resources, workloads, cluster health, runtime security
posture, and operational risk.

## Service map

| Port  | Service                | Role                                            |
| ----- | ---------------------- | ----------------------------------------------- |
| 4001  | `auth-service`         | (Sprint 2) Users, tenants, JWT, RBAC            |
| 4002  | `agent-service`        | (Sprint 3) Agent dispatcher + memory            |
| 4003  | `security-service`     | (Sprint 2) SBOM, vulnerabilities               |
| 4004  | `incident-service`     | (Sprint 1+) Incidents, runbooks, **chains**    |
| 4005  | `compliance-service`   | (Sprint 1+) Controls, evidence, POA&Ms         |
| 4006  | `kubernetes-service`   | **NEW** Read-only K8s inventory                 |
| 4007  | `k8s-health-service`   | **NEW** Health scoring + recommendations        |
| 4008  | `runtime-security-service` | **NEW** Runtime security findings + reports |
| 4009  | `inventory-service`    | **NEW** Asset catalog + graph                   |
| 4010  | `cost-intelligence-service` | **NEW** Cost analysis + recommendations     |
| 4011  | `topology-service`     | **NEW** Service Map / Application Graph         |
| 4012  | `reporting-service`    | **NEW** 6 reports × {json, md, pdf}             |

## Key design decisions

### 1. Provider abstraction for Kubernetes

Each of the inventory-consuming services (`k8s-health`,
`runtime-security`, `inventory`, `cost-intelligence`,
`topology`, `reporting`) talks to a `KubernetesProvider`
interface, with two implementations:

- `fixture` — deterministic in-process data, used in Sprint
  4. Allows each service to be developed and tested without
  a live cluster.
- `live` — placeholder, throws `UnsupportedError` until
  Sprint 5 wires in `@kubernetes/client-node`.

The provider abstraction means the Sprint 5 refactor is a
configuration change, not a code change.

### 2. Engine purity

The five "engine" modules (`k8s-health/engine/health-engine`,
`runtime-security/engine/runtime-security.engine`,
`inventory/engine/inventory.engine`, `cost-intelligence/engine/cost.engine`,
`topology/engine/topology.engine`, `reporting/engine/report.engine`,
`incident/correlation/correlation-engine`) are pure
functions: they take a snapshot and produce a result, with
no I/O. This makes them trivially unit-testable and keeps
the services thin.

### 3. Multi-tenant isolation

Every endpoint requires an `x-tenant-id` header. The
kubernetes-service stores credentials per-tenant in its
cluster repository; the inventory-consumer services
always filter by `tenantId` in their inventory client.
Sprint 5 will move the cluster registry to Postgres and
introduce per-cluster RBAC at the inventory layer.

### 4. Correlation extension

The incident service's correlation engine was extended to
correlate events from:

- Security findings (`VULNERABILITY_DETECTED`)
- SBOM findings (`sbom.finding`, `sbom.vulnerability`)
- CI/CD failures (`cicd.build.failed`, `build.failed`,
  `pipeline.failed`)
- Kubernetes events (`k8s.event`, `k8s.pod.warning`,
  `k8s.deployment.failed`)
- Infrastructure findings (`infrastructure.finding`,
  `cost.finding`)
- Deployment events (`deployment.event`,
  `deployment.succeeded`, `deployment.started`)
- Incident reports (`INCIDENT_CREATED`, `INCIDENT_RESOLVED`)
- Runtime risks (`runtime.risk`)
- Health recommendations (`health.recommendation`)

The engine produces a *causal* chain (root → leaf) and
makes it queryable via `/v1/incidents/chains`.

### 5. Reporting

The reporting service produces six canonical reports:

- Cluster Health Report
- Infrastructure Risk Report
- Runtime Security Report
- Cost Optimization Report
- Topology Report
- Executive Infrastructure Summary

Each report is available in three formats (JSON, Markdown,
PDF). The PDF output is a minimal text-only PDF in Sprint
4; Sprint 5 will add charts, headers, and footers.

## Data flow

```
┌────────────────────┐
│  K8s API / Fixture │
└─────────┬──────────┘
          ▼
┌────────────────────┐         ┌────────────────────┐
│ kubernetes-service │ ──HTTP─▶│ k8s-health-service │
└────────────────────┘         └─────────┬──────────┘
                                        ▼
                          ┌────────────────────────────┐
                          │ runtime-security-service   │
                          └─────────┬──────────────────┘
                                    ▼
              ┌──────────────────┐  ┌──────────────────┐
              │ inventory-service│  │ topology-service │
              └─────────┬────────┘  └─────────┬────────┘
                        ▼                     ▼
              ┌─────────────────────────────────────┐
              │       cost-intelligence-service     │
              └─────────────────┬───────────────────┘
                                ▼
              ┌─────────────────────────────────────┐
              │           reporting-service          │
              └─────────────────┬───────────────────┘
                                ▼
              ┌─────────────────────────────────────┐
              │       AionUi (frontend, SPA)        │
              └─────────────────────────────────────┘
```

## Cross-cutting concerns

- **Observability** — every service emits structured logs
  via `@aicc/shared`'s `createLogger`. Prometheus
  instrumentation is reserved for Sprint 5.
- **Event bus** — the in-process `InMemoryEventBus` is
  the Sprint 4 default. Sprint 5 swaps in Redis Streams.
  The interface is the same.
- **AuthN / AuthZ** — the auth service is the source of
  truth for tenant + user identity. In Sprint 4 every
  service uses the `x-tenant-id` header as a development
  shortcut; the production wiring is in Sprint 5.

## Next steps (Sprint 5)

1. Wire the live `KubernetesProvider` using
   `@kubernetes/client-node`.
2. Add Prometheus metrics to every service.
3. Move the cluster registry, chain repository, and
   correlation buffer to Postgres.
4. Add network-policy inference and Istio / Linkerd
   service-mesh edge discovery to the topology engine.
5. Replace the heuristic utilisation estimates in the
   cost engine with real Prometheus queries.
6. Upgrade the PDF report formatter to use a proper
   templating engine (charts, headers, footers).
