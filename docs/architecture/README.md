# Architecture

> The single source of truth for *what* the system looks like and *why* it
> looks like that. Implementation details live in the code; design rationale
> lives here.

## Documents

| File                                                         | Purpose                                                        | Owner              |
| ------------------------------------------------------------ | -------------------------------------------------------------- | ------------------ |
| [`system-architecture.md`](./system-architecture.md)         | Top-level view: services, data flow, deployment                | PlatformArchitect  |
| [`agent-topology.md`](./agent-topology.md)                   | Agent roles, contracts, lifecycles, and collaboration         | PlatformArchitect  |
| [`event-bus.md`](./event-bus.md)                             | Event bus design, subjects, message contracts                 | PlatformArchitect  |
| [`security-model.md`](./security-model.md)                   | Trust boundaries, multi-tenant isolation, threat model summary | SecurityArchitect  |
| [`authentication-and-security-design.md`](./authentication-and-security-design.md) | AuthN/AuthZ, RBAC, sessions, key management | SecurityArchitect  |
| [`github-integration.md`](./github-integration.md)           | GitHub App integration: PR scanning, SBOM, commenting          | SecurityArchitect  |
| [`../adr/0001-event-bus-transport.md`](../adr/0001-event-bus-transport.md) | Bus transport (Redis Streams → NATS)        | PlatformArchitect  |
| [`../adr/0002-agent-to-agent-communication.md`](../adr/0002-agent-to-agent-communication.md) | Agent comm via bus          | PlatformArchitect  |
| [`../adr/0003-event-schema-format.md`](../adr/0003-event-schema-format.md)     | Avro + JSON-Schema contracts  | PlatformArchitect  |
| [`../adr/0004-six-services-one-database.md`](../adr/0004-six-services-one-database.md) | One DB, schema-per-service | PlatformArchitect  |
| [`../adr/0005-record-architecture-decisions.md`](../adr/0005-record-architecture-decisions.md) | The "we use ADRs" decision | GitOpsManager   |
| [`../adr/0006-monorepo-pnpm.md`](../adr/0006-monorepo-pnpm.md)                 | Monorepo with pnpm workspaces | GitOpsManager   |
| [`../adr/0007-docker-compose-dev.md`](../adr/0007-docker-compose-dev.md)       | Docker Compose for local dev   | GitOpsManager   |

## Diagrams

Diagrams are authored in Mermaid (renders natively in GitHub) and live in this
folder. Update them when the design changes — code is not the source of truth
for "what the system is".

## Reading order

If you are new to the project, read in this order:

1. [`/README.md`](../../README.md) — the elevator pitch.
2. [`/PROJECT_DESCRIPTION.md`](../../PROJECT_DESCRIPTION.md) — the full
   product description.
3. [`system-architecture.md`](./system-architecture.md) — how it hangs together.
4. [`agent-topology.md`](./agent-topology.md) — how the AI agents collaborate.
5. [`event-bus.md`](./event-bus.md) — the nervous system.
6. [`security-model.md`](./security-model.md) — the trust boundaries.
7. [`authentication-and-security-design.md`](./authentication-and-security-design.md) — auth, RBAC, sessions.
8. [`github-integration.md`](./github-integration.md) — the GitHub App story.
9. [`/docs/observability/README.md`](../observability/README.md) — monitoring, logging, metrics.
