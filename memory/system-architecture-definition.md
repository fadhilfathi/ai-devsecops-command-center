---
name: System Architecture Definition
description: Sprint 1 deliverable — 4 architecture docs + 4 ADRs authored by PlatformArchitect
type: project
---

# Sprint 1: System Architecture Definition

**Task ID:** 019ebae2-9da4-7203-a0a9-e6ac08ef9688
**Owner:** PlatformArchitect (slot 019ebae2-9df9-7db0-a45b-c36d235b811e)
**Status:** Completed 2026-06-12
**Related task:** Event Bus & Agent Communication Design (019ebae2-9dc0-7043-8f31-f7067bc98dbb)

## Deliverables (in `docs/architecture/`)

| File | Purpose | Lines |
|---|---|---|
| `README.md` | Index of the architecture doc set | ~70 |
| `system-architecture.md` | High-level system architecture: 6 services, AionUi SPA, API gateway, event bus, data stores, cross-cutting concerns, SLOs, data flows, API conventions | ~300 |
| `agent-topology.md` | AI agent subsystem: roster of 9 agents (TriageAgent, RemediationAgent, IncidentCommander, PostmortemAgent, ComplianceMapper, SBOMWatcher, ThreatIntelAgent, OnboardingAgent, ChatOpsAgent), lifecycle, dispatch mechanics, proposal pipeline, LLM gateway, tools, failure handling, security boundaries | ~310 |
| `event-bus.md` | Event bus: transport (Redis Streams → NATS), `EventBus` interface, topic catalog, schemas/Avro+JSON-Schema, 4 message contracts (`vuln.detected.v1`, `incident.created.v1`, `agent.proposal.created.v1`, `agent.context.handoff.v1`), producer/consumer guidelines, ordering, security, observability, testing, NATS migration path | ~450 |
| `security-model.md` | Security: trust boundaries, identity, OIDC/PKCE, RBAC+PBAC, multi-tenant isolation via Postgres RLS, event bus isolation, secrets in Vault, data protection, network security, AI-specific protections (prompt injection, output validation, hallucination mitigation), audit log, threat model | ~450 |

## Deliverables (in `docs/adr/`)

| File | Decision |
|---|---|
| `README.md` | ADR index + format spec |
| `0001-event-bus-transport.md` | Redis Streams first; NATS JetStream in Sprint 3+; transport-agnostic `EventBus` interface |
| `0002-agent-to-agent-communication.md` | Bus only — no direct agent-to-agent calls; `agent.context.handoff` event pattern |
| `0003-event-schema-format.md` | Avro for machine events; JSON-Schema for proposals; Apicurio registry; backward-compatible |
| `0004-six-services-one-database.md` | Single Postgres cluster, one schema per service, no cross-schema FKs, RLS, migration path to true per-service DBs |

## Key Architectural Choices

1. **6 services** (`auth`, `agent`, `security`, `incident`, `compliance`, `integration`) over shared Postgres with schema isolation.
2. **Event bus** = Redis Streams in Sprint 1; NATS JetStream in Sprint 3+; abstracted by `EventBus` interface.
3. **AI agents are first-class workers** that consume events and emit *proposals*; no direct mutations; bounded autonomy with default `suggest`.
4. **Multi-tenant isolation** enforced at three layers: API gateway tenant routing → application tenant filter → Postgres RLS.
5. **Schemas** are versioned (`*.v1`, `*.v2`); backward-compatible by default; producers and consumers evolve independently.
6. **Open question (mine):** `docs/adr/` is a new convention I introduced; may need Lead's sign-off.

## Cross-Team Coordination Notes

- The Compliance Officer's `docs/compliance/cis-controls-v8.md` exists; the architecture references it in `security-model.md` §13.
- The FullstackEngineer's `backend/services/*/README.md` placeholders exist; my architecture names match them.
- The UIUXEngineer's `frontend/README.md` exists; the AionUi screen list (Dashboard, Assets, Incidents, Vulnerabilities, SBOM, Compliance, Integrations, Settings) in `system-architecture.md` §4.1 should match theirs.
- The SecurityArchitect is doing the deeper auth design; my `security-model.md` is the *model*, theirs is the *implementation*.

## Open Items for Sprint 2

- Formalise the `EventBus` interface in code (`packages/event-bus/src/types.ts`).
- Add a JSON-Schema/Avro codegen step in CI.
- Wire DLQ redrive UI.
- Document a real `agent.context.handoff` end-to-end example.
