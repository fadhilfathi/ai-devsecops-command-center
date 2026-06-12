# Agent service (`@aicc/agent-service`)

> The runtime for AI agents: discovery, dispatch, memory, contracts, and
> policy enforcement.

**Port**: 3002

## Responsibilities

- Load agent definitions from `agents/` at boot, validate their
  contracts, and register them with the platform.
- Dispatch events to the right agent(s), respecting blast radius, tool
  allowlists, token budgets, and timeouts.
- Maintain **memory**: working (per-run), episodic (per-agent),
  semantic (per-tenant).
- Expose a control plane for operators: dry-run, replay, list,
  inspect.
- Mirror every agent run to the **audit log** and to the
  **observability** stack (traces, metrics, logs).

## API (high level)

- `GET    /agents` — list registered agents
- `GET    /agents/:name` — get an agent's contract
- `POST   /agents/:name/run` — dry-run with a synthetic input
- `GET    /agents/:name/runs` — recent runs
- `GET    /runs/:id` — get a specific run (with decision record)
- `GET    /memory/:tenant/:agent` — semantic search
- `GET    /healthz` — liveness
- `GET    /readyz` — readiness
- `GET    /metrics` — Prometheus

## Events

- Consumes: every event that has a registered agent consumer
- Produces: `system.agent.run.started.v1`,
  `system.agent.run.completed.v1`, `system.agent.run.failed.v1`

## See also

- [`/agents/`](../../agents/) — agent definitions
- [`/docs/architecture/agent-topology.md`](../../docs/architecture/agent-topology.md)
