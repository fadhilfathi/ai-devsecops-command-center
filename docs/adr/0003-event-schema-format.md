# ADR-0003: Event Schema Format — Avro with JSON-Schema Fallback

- **Status:** Accepted
- **Date:** 2026-06-12
- **Sprint:** 1
- **Deciders:** Platform Architect, Fullstack Engineer
- **Supersedes:** —
- **Superseded by:** —

## Context

The event bus must carry well-typed messages whose schemas evolve over
time. We must choose a schema format and a compatibility policy.

## Considered Options

1. **JSON only, no schema registry.**
2. **Avro with Confluent/Apicurio schema registry.**
3. **Protobuf with a schema registry.**
4. **JSON-Schema with a registry.**

## Decision

Use **Avro** for machine-produced events (`vuln.detected`,
`incident.created`, etc.) and **JSON-Schema** for human-authored or
extensible events (agent proposals, integration payloads).

The schema registry of choice is **Apicurio** (self-hosted) — open
source, CNCF-aligned, supports both Avro and JSON-Schema, no Kafka
coupling.

Compatibility policy: **backward-compatible** by default. Breaking
changes require a new event-type version (`vuln.detected.v1` →
`vuln.detected.v2`).

## Rationale

- **Avro** gives us compact binary payloads (matters at 5k+ events/s)
  and strong typing with a small dependency footprint.
- **JSON-Schema** for proposals keeps the format human-readable and
  easier to evolve in code, where proposals are dynamic and
  agent-generated.
- **Apicurio** is open source, supports our format choices, and
  doesn't drag in Kafka.
- **Backward compatibility** lets us deploy consumers independently
  of producers, which is critical for an event-driven system.
- **Versioned event types** (`.v1`, `.v2`) keep both versions on the
  wire during migration windows, eliminating "stop the world" upgrades.

## Consequences

### Positive
- Strong typing throughout the bus; no "stringly-typed" payloads.
- Clear upgrade path; producers and consumers can be deployed
  independently.
- Tooling: schema diff, doc generation, code generation for
  TypeScript types.

### Negative
- Added complexity: a schema registry to operate, schema files to
  maintain.
- Developers must learn Avro and JSON-Schema (mitigated by codegen
  from schemas to TypeScript types).

### Risks
- *Schema registry outage* would block event publishing. Mitigation:
  registry is a thin metadata layer; clients cache the latest
  schema locally with a TTL.

## References

- `docs/architecture/event-bus.md` (§6 Schemas & Versioning)
- Apicurio docs: https://www.apicur.io/
