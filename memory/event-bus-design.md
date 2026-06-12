---
name: Event Bus and Agent Communication Design
description: Sprint 1 deliverable — event bus + agent communication design, fully covered in docs/architecture/event-bus.md
type: project
---

# Sprint 1: Event Bus & Agent Communication Design

**Task ID:** 019ebae2-9dc0-7043-8f31-f7067bc98dbb
**Owner:** PlatformArchitect (slot 019ebae2-9df9-7db0-a45b-c36d235b811e)
**Status:** Completed 2026-06-12
**Note:** This task's content is **fully contained** in `docs/architecture/event-bus.md` (which was also produced for the System Architecture Definition task). No separate file was created to avoid duplication.

## What Was Delivered (in `docs/architecture/event-bus.md`)

- **Transport selection** — Redis Streams for Sprint 1 (already in stack, sufficient for 5k events/s); NATS JetStream in Sprint 3+ when throughput exceeds ~20k/s or multi-region is needed.
- **Transport-agnostic `EventBus` interface** — `publish`, `subscribe`, `request`, `replay`, `health`. Application code does not import the transport SDK directly.
- **Topic catalog** — 26 named topics across `asset.*`, `vuln.*`, `sbom.*`, `incident.*`, `control.*`, `evidence.*`, `integration.*`, `scan.*`, `user.*`, `role.*`, `agent.*`.
- **Message contracts (sample)** — `vuln.detected.v1`, `incident.created.v1`, `agent.proposal.created.v1`, `agent.context.handoff.v1` with JSON examples.
- **Schema/versioning** — Apicurio registry; Avro for machine events, JSON-Schema for proposals; backward-compatible by default; versioned event types.
- **Producer guidelines** — emit don't notify, one event per state change, event-carried state transfer, **Outbox pattern** for transactional publishing.
- **Consumer guidelines** — idempotency via `event_dedupe` table; bounded retries with exponential backoff; DLQ routing.
- **Pub/sub vs point-to-point vs request/reply** — explicit guidance for when to use each.
- **Ordering & consistency** — per-aggregate ordering via partition key; no read-your-writes across services.
- **Security on the bus** — tenant ID on every event, payload encryption, no PII, consumer-side tenant filtering.
- **Observability** — Prometheus metrics (lag, throughput, error rate), structured logs, OpenTelemetry traces, Grafana dashboard, alerts.
- **Testing** — in-memory mock, contract tests (Pact-style), soak tests, chaos tests.
- **NATS migration path** — interface parity, dual-write, group-by-group cutover.

## Companion Documents

- `docs/adr/0001-event-bus-transport.md` — Why Redis Streams first; when to move to NATS.
- `docs/adr/0002-agent-to-agent-communication.md` — Why no direct agent-to-agent calls; `agent.context.handoff` pattern.
- `docs/adr/0003-event-schema-format.md` — Why Avro + JSON-Schema, Apicurio, backward-compat.
- `docs/architecture/agent-topology.md` §5 — How the bus serves agent-to-agent coordination.

## Open Items for Sprint 2

- Implement `packages/event-bus` with `RedisStreamsEventBus` and a `MockEventBus` for tests.
- Set up Apicurio in `docker-compose.yml`.
- Codegen TypeScript types from Avro/JSON-Schema in CI.
- Add `eventbus.request` correlation tests.
- Build the stream visualiser UI for local dev.
