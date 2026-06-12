# System Architecture

> **Status**: Sprint 1 draft (GitOpsManager). PlatformArchitect to publish
> the canonical, detailed version.
> **Owner**: PlatformArchitect (canonical) / GitOpsManager (this draft)
> **Last reviewed**: 2026-06-12

## Purpose

This document describes the AI-DevSecOps Command Center at the system level:
its components, the data that flows between them, the trust boundaries they
sit on, and the deployment topology. It is intentionally implementation-light
— for "how does service X work", read the service README.

## Logical view

```
                       ┌─────────────────────────────┐
                       │        AionUi (SPA)         │
                       │  Dashboard · Assets · …     │
                       └──────────────┬──────────────┘
                                      │ HTTPS / WSS
                                      ▼
                ┌──────────────────────────────────────────┐
                │              API Gateway                  │
                │  (auth · rate-limit · trace-id injection) │
                └──────────────┬───────────────────────────┘
                               │
       ┌───────────┬───────────┼───────────┬───────────┬───────────┐
       ▼           ▼           ▼           ▼           ▼           ▼
   ┌────────┐ ┌────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐
   │  Auth  │ │ Agent  │ │ Security │ │Incident │ │Compliance│ │Integration│
   │service │ │service │ │ service  │ │ service │ │ service  │ │  service │
   └───┬────┘ └───┬────┘ └────┬─────┘ └────┬────┘ └────┬─────┘ └────┬─────┘
       │          │            │            │            │            │
       └──────────┴─────┬──────┴────────────┴────────────┴────────────┘
                        │           Event bus (Redis Streams / NATS)
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌──────────┐    ┌──────────────┐
   │Postgres │    │  Redis   │    │ Object store │
   │(primary)│    │  (cache, │    │ (evidence,   │
   │         │    │  streams)│    │  SBOMs)      │
   └─────────┘    └──────────┘    └──────────────┘
                        │
                        ▼
               ┌─────────────────────┐
               │   Observability     │
               │ Prometheus · Loki   │
               │ OTel · Grafana      │
               └─────────────────────┘
```

> The diagram above is a sketch. The final Mermaid diagram is being authored
> by the PlatformArchitect; see the rendered version in this folder.

## Components

### Frontend — AionUi

- A single-page application (Vite + React + TypeScript).
- Eight product surfaces: Dashboard, Assets, Incidents, Vulnerabilities,
  SBOM, Compliance, Integrations, Settings.
- Talks to the backend only over the API Gateway, never directly to services.
- Subscribes to a WebSocket for real-time updates (incidents, agent activity,
  scan progress).

### API Gateway

- Single ingress for the SPA.
- Responsibilities: TLS termination, request authentication (JWT), rate
  limiting, request validation, trace-id injection, CORS, request logging.

### Backend services (six)

| Service          | Port | Responsibility                                                  |
| ---------------- | ---- | --------------------------------------------------------------- |
| `auth`           | 3001 | Identity, RBAC, sessions, multi-tenant isolation               |
| `agent`          | 3002 | Agent runtime: scheduling, dispatch, memory, contract registry |
| `security`       | 3003 | Asset inventory, vulnerabilities, SBOM                          |
| `incident`       | 3004 | Incident lifecycle, correlation, response playbooks            |
| `compliance`     | 3005 | Control mapping (CIS / NIST), evidence collection, attestations |
| `integration`    | 3006 | External system adapters (GitHub, GitLab, scanners, etc.)       |

All services are Node.js + TypeScript on Fastify, exposing JSON over HTTP and
subscribing to a shared event bus.

### Event bus

- Default: **Redis Streams** (single-binary, low ops cost).
- Optional: **NATS JetStream** (for multi-region or higher fan-out).
- Every event is a typed message contract; see [`event-bus.md`](./event-bus.md).

### Datastores

- **PostgreSQL** — system of record. One database, **schema-per-service**
  (see [`../adr/0004-six-services-one-database.md`](../adr/0004-six-services-one-database.md)).
- **Redis** — cache, ephemeral state, event bus, rate limit buckets.
- **Object store** (S3-compatible) — evidence, SBOMs, scan artifacts.

### Observability

See [`../observability/README.md`](../observability/README.md).

- **OpenTelemetry** for traces and metrics (OTLP export).
- **Prometheus** for metrics scraping (`/infra/observability/prometheus/`).
- **Loki** for log aggregation (`/infra/observability/logs/`).
- **Grafana** for dashboards (`/infra/observability/grafana/`).

## Data flow

A typical "vulnerability discovered in a PR" flow:

1. GitHub sends a webhook to `integration`.
2. `integration` validates the signature, normalizes the payload, and emits
   `pr.opened` to the event bus.
3. `agent` consumes `pr.opened` and dispatches the **SBOM agent** and the
   **vulnerability scan agent**.
4. `security` consumes the agents' outputs, stores findings, and emits
   `vulnerability.detected`.
5. `compliance` consumes `vulnerability.detected`, maps it to controls, and
   emits `evidence.attached`.
6. `incident` correlates the finding with prior context; if a sev-critical
   CVE matches known exploited lists, it emits `incident.opened`.
7. The WebSocket fan-out pushes the new incident to the Dashboard for
   operators in real time.

## Trust boundaries

| Boundary                 | Inside                                | Outside                          |
| ------------------------ | ------------------------------------- | -------------------------------- |
| **Browser → Gateway**    | Authenticated, validated              | Untrusted user input             |
| **Gateway → Services**   | Authenticated, mTLS, traced           | Trusts Gateway                   |
| **Service → Event bus**  | Service identity                      | Trusts bus, but mTLS in prod     |
| **Service → Postgres**   | Per-service role, TLS                 | Trusts service role              |
| **Service → Object store** | Scoped tokens per service           | Trusts scoped token              |
| **Service → External**   | Outbound via `integration` only       | Public internet                  |

## Deployment topology

- **Dev / local**: Docker Compose (see `docker-compose.yml`).
- **Staging / prod**: Kubernetes (manifests in `infra/kubernetes/`).
  - One Deployment per service.
  - Postgres: managed (RDS / Cloud SQL / Crunchy) or in-cluster operator.
  - Redis: managed (ElastiCache / Memorystore) or in-cluster with HA.
  - Object store: managed (S3 / GCS) or MinIO in-cluster.
  - Ingress: NGINX or cloud LB; cert-manager for TLS.

## Quality attributes

The architecture optimizes for the following:

- **Correctness** — strict typing, contracts at every boundary, evidence by default.
- **Operability** — every service exposes health, metrics, logs, traces.
- **Auditability** — every state-changing action produces an audit record.
- **Extensibility** — adding a new agent or integration is a typed, documented
  contract, not a code change to the platform.
- **Portability** — runs the same on a laptop and on a hardened cluster.

## Non-goals

- This is **not** a SIEM replacement. We integrate with SIEMs; we are not one.
- This is **not** a ticketing system. We integrate with Jira/Linear/etc.
- This is **not** an IaC platform. We read IaC outputs; we do not own them.

## Open questions

> Tracked here; resolved ADRs are in [`/docs/adr/`](../adr/).

- **Q1**: Will we run our own LLM gateway, or front a third-party (e.g.
  OpenRouter, AionRs) with caching and policy? See `docs/adr/`.
- **Q2**: Single-tenant per cluster, or multi-tenant in a cluster with hard
  namespace isolation? See `security-model.md`.
- **Q3**: How do we version event contracts without breaking consumers?
  Drafting `docs/adr/0007-event-versioning.md`.

## See also

- [`agent-topology.md`](./agent-topology.md)
- [`event-bus.md`](./event-bus.md)
- [`security-model.md`](./security-model.md)
- [`/docs/adr/`](../adr/)
