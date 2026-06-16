# Runtime Security

Sprint 4 adds a runtime-security intelligence service that
detects Kubernetes runtime risks across the tenant's clusters
and produces a per-cluster / per-tenant `RuntimeSecurityReport`.

## Detection rules

The rule set lives in
`backend/services/runtime-security/src/engine/rules.ts`.
Each rule is a pure function that takes a snapshot of
inventory (pods, workloads, services) and returns zero or
more `RuntimeRisk` findings.

| ID         | Name                                | Default level   |
| ---------- | ----------------------------------- | --------------- |
| AICC-RT-001 | Privileged container              | critical        |
| AICC-RT-002 | hostPath volume mount             | high (critical for sensitive paths) |
| AICC-RT-003 | Root user execution               | high            |
| AICC-RT-004 | Dangerous Linux capability        | high (critical for SYS_ADMIN / ALL) |
| AICC-RT-005 | Weak / missing SecurityContext    | medium          |
| AICC-RT-006 | Risky ServiceAccount usage        | medium          |
| AICC-RT-007 | Risky RBAC binding                | high (stub for Sprint 5) |
| AICC-RT-008 | Missing resource limits           | low             |
| AICC-RT-009 | Image tag not pinned to digest    | medium (AICC extension) |

## Report

`RuntimeSecurityReport` is the rollup:

- `riskLevel` — highest level across findings
  (`critical` / `high` / `medium` / `low`).
- `score` — 0..100; higher = safer. Penalty = 8 × critical +
  4 × high + 2 × medium + 1 × low.
- `counts` — per-level counters.
- `categoryCounts` — per-category counters.
- `findings` — full finding list.
- `recommendations` — top-N (10) recommendations, one per
  rule, sorted by level then by affected count.

## Endpoints

| Method | Path                                          | Description                  |
| ------ | --------------------------------------------- | ---------------------------- |
| GET    | `/v1/runtime-security/rules`                  | List active rules            |
| GET    | `/v1/runtime-security/risks`                  | Per-finding risk list        |
| GET    | `/v1/runtime-security/risks/:id`              | Single finding detail        |
| POST   | `/v1/runtime-security/scan`                   | Trigger a re-scan            |
| GET    | `/v1/runtime-security/report`                 | Tenant-wide rollup report    |
| GET    | `/v1/runtime-security/report/cluster/:id`     | Per-cluster rollup report    |

## See also

- `docs/kubernetes/` — Kubernetes service endpoints.
- `docs/architecture/sprint-4/` — Sprint 4 architecture
  notes.
- `backend/models/infrastructure/runtime-risk.model.ts` —
  the canonical Zod schema.
