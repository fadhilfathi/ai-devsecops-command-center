# Memory Index — MiniMax Command Center Team

## Decisions
- [decision-pnpm-turborepo.md](./decision-pnpm-turborepo.md) — Sprint 2 toolchain: pnpm + Turborepo (no npm migration)

## Sprint 1 — COMPLETE ✅
- [sprint-1-status.md](./sprint-1-status.md) — Sprint 1 final status (232 files, 16,889 insertions, all 10 success criteria met)
- [sprint-1-retrospective.md](./sprint-1-retrospective.md) — PlatformArchitect retrospective: contributions, conventions locked, Sprint 2 hot list
- [sprint-1-task-board.md](./sprint-1-task-board.md) — sprint 1 task assignments

## Per-agent work
- [system-architecture-definition.md](./system-architecture-definition.md) — PlatformArchitect: system architecture
- [event-bus-design.md](./event-bus-design.md) — PlatformArchitect: event bus design
- [monitoring-architecture.md](./monitoring-architecture.md) — SREEngineer: monitoring, logging, metrics architecture
- [gitops-manager-sprint-1.md](./gitops-manager-sprint-1.md) — GitOpsManager: repo, CI/CD, contributor docs, ADRs 0005-0007

## Open items (cross-team, as of 2026-06-12)

| ID  | Item                                                                | Owner             | Status         | Waiting on                                          |
| --- | ------------------------------------------------------------------- | ----------------- | -------------- | --------------------------------------------------- |
| O-1 | **Sprint 2 kickoff** (Trivy + DepTrack, agent runtime v1, WebSocket) | Lead              | awaiting kickoff | Lead                                               |
| O-2 | **FullstackEngineer code PR** (6-package split + Turborepo + Prisma + RS256 + port renumber) | FullstackEngineer | in flight       | FullstackEngineer "docs PR is unblocked" marker     |
| O-3 | **Docs PR (mine, gated on O-2)** within 24h of unblock marker        | GitOpsManager     | queued          | O-2 marker                                          |
| O-4 | **SRE Jinja macro cleanup** (small docs-only follow-up; not in Sprint 2 backend reshape) | SREEngineer | optional        | SREEngineer                                         |

All Sprint 1 follow-up items (Loki config, runbook templating, stale paths, dev/prod split) are resolved — see `observability-layout.md` "Closed items (historical)" section.

## Cross-cutting
- [project-conventions.md](./project-conventions.md) — locked naming, layout, stack, ownership
- [feedback-coordination.md](./feedback-coordination.md) — lessons from Sprint 1 parallel-work coordination
- [observability-layout.md](./observability-layout.md) — dev/prod observability file layout, open items (Loki, runbook templating)
- [sprint-2-coordination.md](./sprint-2-coordination.md) — backend package split + Turborepo migration commitments
