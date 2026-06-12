# Architecture Decision Records (ADRs)

This folder contains the **Architecture Decision Records** for the
AI-DevSecOps Command Center. Each ADR captures an important
architectural decision: its context, the options considered, the
decision made, and its consequences.

## Index

| # | Title | Status | Date |
|---|---|---|---|
| [0001](./0001-event-bus-transport.md) | Event Bus Transport — Redis Streams First, NATS JetStream Later | Accepted | 2026-06-12 |
| [0002](./0002-agent-to-agent-communication.md) | Agent-to-Agent Communication — Bus Only, No Direct Calls | Accepted | 2026-06-12 |
| [0003](./0003-event-schema-format.md) | Event Schema Format — Avro with JSON-Schema Fallback | Accepted | 2026-06-12 |
| [0004](./0004-six-services-one-database.md) | Six Services, One Database, Schema-per-Service | Accepted | 2026-06-12 |

## Format

We use a lightweight ADR format inspired by
[Michael Nygard's](https://github.com/adr/madr) MADR:

```
# ADR-NNNN: Title

- Status: Proposed | Accepted | Deprecated | Superseded by ADR-XXXX
- Date: YYYY-MM-DD
- Sprint: N
- Deciders: …
- Supersedes / Superseded by: …

## Context
What is the issue? What are the forces at play?

## Considered Options
What were the alternatives?

## Decision
What did we decide?

## Rationale
Why?

## Consequences
Positive, Negative, Risks.

## References
Links to related docs.
```

## When to Write an ADR

Write an ADR when the decision:

- Is **architectural** (shapes the system's structure, not just its
  implementation).
- Is **hard to reverse** (database choices, communication patterns,
  identity model, schema format).
- Has **multiple reasonable options** with real trade-offs.
- **Future engineers** will want to understand *why* we chose what
  we chose.

If a decision is reversible and local, prefer a code comment or a
short note in the relevant document.

## Lifecycle

- **Proposed:** the team is discussing; not yet binding.
- **Accepted:** the decision is in force.
- **Deprecated:** no longer applies but kept for history.
- **Superseded by ADR-XXXX:** a newer ADR replaces this one; this
  doc remains for context.

We do **not** delete ADRs. They are append-only history.
