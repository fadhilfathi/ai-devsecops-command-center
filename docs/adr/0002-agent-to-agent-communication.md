# ADR-0002: Agent-to-Agent Communication — Bus Only, No Direct Calls

- **Status:** Accepted
- **Date:** 2026-06-12
- **Sprint:** 1
- **Deciders:** Platform Architect
- **Supersedes:** —
- **Superseded by:** —

## Context

The AI agent subsystem has multiple agents (TriageAgent,
RemediationAgent, IncidentCommander, etc.) that need to coordinate
on shared work items (e.g. a triaged vulnerability is now ready for a
remediation PR). We must decide how agents hand off work to each
other.

## Considered Options

1. **Direct agent-to-agent RPCs** (e.g. agent A calls agent B's HTTP
   endpoint).
2. **Event bus only** — agents communicate exclusively through
   domain events, handoff events, and the proposal pipeline.
3. **Hybrid** — bus for state changes, RPC for synchronous
   collaboration on the same case.

## Decision

Adopt **Option 2: Event bus only.** Agents do not call each other
directly, even for collaboration on the same case.

The pattern for "agent A has decided that agent B should pick up the
case" is:

1. Agent A emits an `agent.context.handoff` event with a `case_id`
   and a `snapshot` of context.
2. Agent B's dispatcher matches the event and uses the snapshot to
   seed its own context window.
3. Agent B's run proceeds independently and emits its own proposals.

## Rationale

- **Decoupling.** Producers don't know consumers; the system stays
  composable and agents can be added/removed without code changes
  elsewhere.
- **Observability.** Every inter-agent handoff is a durable,
  inspectable event in the bus. We get a complete case timeline for
  free.
- **Replayability.** New agents (or new versions) can re-read the
  case timeline and reason about the full history.
- **Failure isolation.** A direct call from A to B makes A's success
  depend on B's availability. With the bus, A succeeds as soon as it
  emits the handoff; B can be down, retried, or replaced.
- **Bounded blast radius.** The bus is the *only* surface where agent
  authority is exercised (via the proposal pipeline). Adding a new
  communication channel would expand the threat model.

## Consequences

### Positive
- Cleaner architecture; agents are truly independent workers.
- Strong audit trail; every cross-agent action is an event.
- Easier to test (record/replay the bus).
- Lower coupling → easier to scale agents independently.

### Negative
- Higher latency for some interactions (one event hop instead of
  an in-process call). Acceptable for our use cases.
- Slightly more complex debugging: the call stack is spread across
  multiple runs and the bus.

### Risks
- *Latent "telephone game" between agents* if the snapshot grows
  stale. Mitigation: snapshots are small, structured, and include
  a `snapshot_version`; consumers fetch fresh data via tools when
  they need it.
- *Lost handoff events* would orphan a case. Mitigation: handoff
  events use the outbox pattern; consumers use idempotent
  processing and re-delivery.

## References

- `docs/architecture/agent-topology.md` (§5 Agent-to-Agent
  Communication)
- `docs/architecture/event-bus.md` (§7.4 `agent.context.handoff.v1`)
- ADR-0001 (Event Bus Transport)
