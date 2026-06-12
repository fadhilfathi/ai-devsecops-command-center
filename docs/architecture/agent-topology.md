# Agent Topology

> **Status**: Sprint 1 draft (GitOpsManager). PlatformArchitect to publish
> the canonical, detailed version.
> **Owner**: PlatformArchitect (canonical) / GitOpsManager (this draft)

## Purpose

This document describes the **AI agents** that live inside the Command
Center: their roles, the contracts they expose, the events they consume
and produce, and how they collaborate.

For the underlying runtime (how a single agent is executed, how prompts are
cached, how tokens are counted) see `backend/services/agent/`. Note that
the agent runtime in this project is implemented in **Python 3.11** (for
its strong Trivy/Dependency-Track integration story); the contracts and
contracts-described-here are language-agnostic.

## Agent model

An **agent** is a typed, versioned unit of work. It has:

- A **name** (e.g. `sbom-generator`)
- A **version** (SemVer)
- A **role** it belongs to (e.g. `security`)
- An **input contract** (JSON schema or TypeScript type)
- An **output contract** (JSON schema or TypeScript type)
- A set of **events consumed** (e.g. `pr.opened`)
- A set of **events produced** (e.g. `sbom.generated`)
- A **runtime adapter** (which LLM / tool framework executes it)
- A **declared model tier** (cheap, balanced, premium)
- A **declared max-token budget** and **timeout**
- A **declared blast radius** (read-only / writes findings / opens incidents)

This shape is enforced in code by the agent runtime; an agent that doesn't
declare all of these won't load.

## Core agents

### Security domain

| Agent                | Consumes                       | Produces                          | Tier    | Notes |
| -------------------- | ------------------------------ | --------------------------------- | ------- | ----- |
| `sbom-generator`     | `pr.opened`, `repo.scan`       | `sbom.generated`                  | cheap   | CycloneDX 1.5; offline-capable |
| `vuln-scanner`       | `sbom.generated`, `pr.opened`  | `vulnerability.detected`          | balanced| Uses multiple CVE feeds |
| `secrets-detector`   | `pr.opened`, `pr.synchronize`  | `secret.found`                    | balanced| Never echoes secret content |
| `license-auditor`    | `sbom.generated`               | `license.flagged`                 | cheap   |  |
| `container-scanner`  | `image.built`                  | `vulnerability.detected`         | premium |  |

### Incident domain

| Agent                | Consumes                       | Produces                          | Tier    |
| -------------------- | ------------------------------ | --------------------------------- | ------- |
| `incident-correlator`| `vulnerability.detected`, `secret.found` | `incident.opened`      | premium |
| `triage-assistant`   | `incident.opened`              | `incident.classified`             | balanced|
| `playbook-runner`    | `incident.classified`          | `incident.action.*`               | cheap   |
| `postmortem-drafter` | `incident.resolved`            | `postmortem.drafted`              | balanced|

### Compliance domain

| Agent                | Consumes                       | Produces                          | Tier    |
| -------------------- | ------------------------------ | --------------------------------- | ------- |
| `control-mapper`     | `vulnerability.detected`, `evidence.attached` | `control.mapped`     | balanced|
| `evidence-collector` | `control.mapped`               | `evidence.attached`               | cheap   |
| `attestation-builder`| `evidence.attached`            | `attestation.built`               | balanced|

### Integration domain

| Agent                | Consumes                       | Produces                          | Tier    |
| -------------------- | ------------------------------ | --------------------------------- | ------- |
| `github-pr-commenter`| `vulnerability.detected`, `secret.found` | `pr.comment.posted`  | cheap   |
| `jira-issue-creator` | `incident.opened`              | `ticket.linked`                   | cheap   |
| `slack-notifier`     | `incident.opened`, `incident.resolved` | `notification.sent`     | cheap   |

> The lists above are illustrative; they will evolve as we discover more
> needs. The agent registry is the source of truth.

## Collaboration patterns

### Sequential pipeline

```
pr.opened → sbom-generator → vuln-scanner → incident-correlator
```

The output of each agent is the input of the next. Implemented as a
**pipeline** event contract: each agent's "produced" event carries a
`correlation_id` that lets downstream consumers continue the chain.

### Fan-out / fan-in

```
image.built
  ├── container-scanner
  ├── license-auditor
  └── secrets-detector
        └── (fan-in) → incident-correlator
```

The runtime supports `parallel` and `join` operators in the agent DAG.

### Human-in-the-loop

Some agents (e.g. `attestation-builder`, `triage-assistant`) emit an
`approval.requested` event. The platform pauses execution; an operator
approves via the UI; the platform emits `approval.granted` and the agent
resumes. Approvals are themselves an audit record.

## Memory

Agents have three kinds of memory:

- **Working memory** — the prompt context for the current run. Discarded
  after the run unless the agent asks to persist.
- **Episodic memory** — past runs of this agent, indexed by `correlation_id`
  and inputs. Used for "have we seen this before?".
- **Semantic memory** — embeddings of past findings, used for similarity
  search. Stored in a vector index.

Memory is **scoped to a tenant**. The runtime never crosses tenant
boundaries when reading or writing memory.

## Lifecycle

```
defined → validated → published → scheduled (if any) → running → completed/failed → archived
```

- `defined` — contract is in the registry, not yet runnable
- `validated` — contract passes schema, dry-run passes, prompt renders
- `published` — available for dispatch
- `scheduled` — has a cron / trigger
- `running` — currently executing
- `completed` / `failed` — terminal
- `archived` — superseded by a new version

## Versioning

- Agents are SemVer'd.
- A **major** version bump means the input or output contract changed in a
  breaking way. Old and new versions coexist during a deprecation window.
- The event bus tags every event with `agent_version`; consumers can pin
  to a version or follow the latest.

## Observability

Every agent run produces:

- A **trace** (OTel span tree) showing each LLM call, tool call, and event.
- A **structured log** stream with the same correlation ID.
- A **metric** series: runs, errors, tokens, duration, p50/p95/p99.
- A **decision record** — what the agent decided and why (its final prompt
  response, the tools it called, and the inputs).

This is a hard requirement: an agent whose decisions are not traceable
does not get promoted to `published`.

## See also

- [`event-bus.md`](./event-bus.md) — the events above
- [`security-model.md`](./security-model.md) — blast radius and authorization
- [`../observability/`](../observability/) — observability for agent runs
- [`/agents/`](../agents/) — agent source code and contracts
