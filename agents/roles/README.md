# Agent Roles

This directory hosts the role-specific agent packages. Each role groups agents
that share a domain (security, incident, compliance, SRE) and common tooling.

## Planned structure (Sprint 2+)

```
roles/
├── security/      # sbom-generator, vuln-scanner, secrets-detector, …
├── incident/      # incident-correlator, triage-assistant, …
├── compliance/    # control-mapper, evidence-collector, audit-reporter
├── sre/           # anomaly-detector, runbook-generator
└── meta/          # architect-tier advisor agents
```

Each role package exports a `register(runtime)` function that the runtime calls
on startup to bind all agents in that role to the bus.

The full agent roster is in
[`docs/architecture/agent-topology.md`](../../docs/architecture/agent-topology.md).
