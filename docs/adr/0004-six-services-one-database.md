# ADR-0004: Six Services, One Database, Schema-per-Service

- **Status:** Accepted
- **Date:** 2026-06-12
- **Sprint:** 1
- **Deciders:** Platform Architect, Fullstack Engineer
- **Supersedes:** —
- **Superseded by:** —

## Context

Sprint 1 plans six backend services (auth, agent, security, incident,
compliance, integration). The question is how to organise persistence:
one database per service from day one, or share a database with schema
isolation?

## Considered Options

1. **One database per service** (database-per-service pattern).
2. **Single database, one schema per service** (shared DB, logical
   isolation).
3. **Single database, shared tables** (modular monolith).

## Decision

Adopt **Option 2: a single Postgres cluster with one schema per
service**, with **no cross-schema foreign keys**.

Each service:
- Owns its schema and the tables in it.
- Exposes data to other services only through its API.
- Uses Row-Level Security for multi-tenant isolation within its
  schema.

Migrate to **Option 1** (database-per-service) when *any* of:
- A service's contention affects another.
- Compliance requires it (e.g. a tenant wants their data in a
  specific region).
- The team has the operational maturity to run 6+ Postgres
  instances.

## Rationale

- **Operational simplicity in Sprint 1.** One connection pool, one
  backup, one set of migrations tooling. Six databases from day one
  would slow us down without buying us anything at our current
  scale.
- **Logical isolation preserves the architectural boundary.** Cross-
  schema FKs are forbidden, so the migration to database-per-service
  is mechanical: dump schema N, restore into its own database,
  update connection string.
- **RLS gives us defense in depth** even within a single DB.
- **Teams can develop and migrate their own schema** without
  coordinating with other teams, as long as the API contract is
  honoured.

## Consequences

### Positive
- Faster Sprint 1 velocity.
- Clear migration path to true database-per-service.
- Cross-team interference still prevented by API contracts and
  schema boundaries.

### Negative
- *Logical* isolation is weaker than *physical* isolation. A
  compromised DBA could in principle read across schemas (we
  mitigate with RLS, separate roles per service, and audit).
- A noisy neighbour in one schema can affect another's connection
  pool (we mitigate with PgBouncer + per-service pool sizes).

### Risks
- *Inertia*: we may defer the per-service migration indefinitely.
  Mitigation: review the trigger conditions quarterly.

## References

- `docs/architecture/system-architecture.md` (§4.3 Backend Services)
- `docs/architecture/security-model.md` (§6.1 Row-Level Security)
