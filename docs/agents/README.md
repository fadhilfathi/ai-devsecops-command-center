# Agents

> AI agents live in two places:
> 1. The **runtime** in `backend/services/agent/` — the dispatcher,
>    memory, contract registry.
> 2. The **definitions** in `agents/` — the typed contracts, prompt
>    templates, and tool allowlists for each agent.

This folder explains the **agent topology** at a design level.
See [`/docs/architecture/agent-topology.md`](../architecture/agent-topology.md)
for the canonical list of agents, the events they consume/produce, and
their declared blast radius.

## Folder layout

```
agents/
├── core/         # base classes, contracts, runtime adapters (LLM-agnostic)
├── roles/        # role-specific code (security, incident, compliance, integration)
└── skills/       # reusable skills agents can compose
```

## An agent, in code

```ts
import { defineAgent } from '@aicc/agent-core';

export default defineAgent({
  name: 'sbom-generator',
  version: '1.0.0',
  role: 'security',
  consumes: ['integration.github.pr.opened.v1'],
  produces: ['security.sbom.generated.v1'],
  blastRadius: 'read-only',
  modelTier: 'cheap',
  maxTokens: 4096,
  timeoutMs: 60_000,
  input: /* JSON schema */,
  output: /* JSON schema */,
  tools: ['fetch-repo-tree', 'read-file', 'parse-manifest'],
  prompt: /* ... */,
  run: async (input, ctx) => {
    // pure function: input + ctx → output
    // no I/O unless through declared tools
  }
});
```

The runtime refuses to dispatch an agent that doesn't satisfy the contract
above.

## Authoring an agent

1. Create a folder under `agents/roles/<role>/<agent-name>/`.
2. Add `index.ts` exporting a `defineAgent({...})` object.
3. Add an `index.test.ts` with at least one golden-input test.
4. Add a `README.md` describing the agent's purpose, contract, and
   examples of input/output.
5. Register the agent in `agents/roles/<role>/index.ts`.

## Memory

- **Working memory** is the current prompt context.
- **Episodic memory** is the past runs of this agent, indexed by
  `correlation_id` and input hash. Use it for "have I seen this input
  before?".
- **Semantic memory** is embeddings of past outputs; the runtime
  exposes `ctx.semantic.search(query)` to find similar prior findings.

All memory is **tenant-scoped**.

## Safety

- Every agent declares a **blast radius**. The runtime enforces it: an
  agent with `read-only` cannot write to the database or call a
  state-changing tool.
- The runtime enforces a **token budget** per run and per tenant per day.
- Tool calls go through a **policy filter**; a tool not in the agent's
  allowlist is rejected.
- LLM inputs and outputs are logged (with secrets redacted) and retained
  for the audit period.
