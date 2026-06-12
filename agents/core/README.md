# Agent Core Runtime

This directory will contain the Python agent runtime and base classes for the
Command Center's agent mesh.

## Planned contents (Sprint 2)

- `runtime.py` — agent lifecycle (load → register → dispatch → observe)
- `base.py` — `Agent` and `Skill` base classes
- `registry.py` — typed agent registration
- `dispatcher.py` — event-driven dispatch loop
- `contracts.py` — input/output contract decorators
- `telemetry.py` — agent-level metrics and tracing

The runtime is intentionally thin: agents are typed units of work, and the
runtime is just the executor plus the bus connection.

See [`docs/architecture/agent-topology.md`](../../docs/architecture/agent-topology.md)
for the agent model, and
[`docs/architecture/event-bus.md`](../../docs/architecture/event-bus.md) for the
transport.
