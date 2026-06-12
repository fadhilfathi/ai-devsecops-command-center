# ADR-0001: Event Bus Transport — Redis Streams First, NATS JetStream Later

- **Status:** Accepted
- **Date:** 2026-06-12
- **Sprint:** 1
- **Deciders:** Platform Architect, SRE Engineer, Security Architect
- **Supersedes:** —
- **Superseded by:** —

## Context

The AI-DevSecOps Command Center requires an event bus for inter-service
and agent-to-agent communication. The platform must support at-least-once
delivery, ordered processing per aggregate, replayability, and
multi-tenant isolation. We must choose a transport for Sprint 1 and
identify a migration path for future scale.

## Considered Options

1. **Redis Streams (Sprint 1) + NATS JetStream (Sprint 3+).**
2. **Apache Kafka from day one.**
3. **RabbitMQ.**
4. **NATS JetStream from day one.**

## Decision

Adopt **Redis Streams** as the Sprint 1 transport, behind a
transport-agnostic `EventBus` interface. Plan to migrate to
**NATS JetStream** in Sprint 3+ when sustained throughput exceeds
~20k events/s or multi-region active-active is required.

## Rationale

- **Redis is already in the stack** for caching, rate-limiting, and
  session storage. Reusing it avoids a new operational dependency in
  early sprints.
- **Throughput is sufficient** for Sprint 1/2 targets (5k events/s per
  cluster).
- **Consumer groups** in Redis Streams give us the fan-out and
  load-balancing semantics we need.
- **The `EventBus` interface** decouples application code from the
  transport, so the Sprint 3+ migration is a one-line config change
  plus a parallel-run window.
- **Kafka** is overkill for our current scale and adds substantial
  operational cost (ZooKeeper/KRaft, schema registry, Connect
  cluster). We can adopt it later if NATS proves insufficient.
- **RabbitMQ** lacks the replay/history semantics we need for new
  consumers to backfill from history.
- **NATS from day one** would mean carrying a brand-new operational
  dependency during the platform's first critical sprints. Better to
  validate the design against a familiar transport and migrate once
  the design is stable.

## Consequences

### Positive
- Lower operational overhead in Sprint 1.
- No new team skills required.
- Clean migration path defined.

### Negative
- Redis Streams has weaker ecosystem tooling than Kafka (e.g.
  connectors, schema registry maturity). We mitigate with Avro/JSON
  Schema + Apicurio.
- The migration to NATS is a non-trivial effort; we must keep the
  interface discipline high.

### Risks
- *Throughput ceiling reached earlier than expected.* Mitigation:
  load tests in Sprint 2; pre-provisioned migration playbook.
- *Vendor-style lock-in to Redis semantics* creeping into application
  code. Mitigation: lint rule forbidding `ioredis`/`node-redis`
  imports outside `@cdc/event-bus`.

## References

- `docs/architecture/event-bus.md` (§3 Transport Selection, §17
  Migration Path)
- ADR-0002 (Agent-to-Agent Communication)
- ADR-0003 (Event Schema Format)
