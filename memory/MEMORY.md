# Memory Index — MiniMax Command Center Team

## Decisions
- [decision-pnpm-turborepo.md](./decision-pnpm-turborepo.md) — Sprint 2 toolchain: pnpm + Turborepo (no npm migration)

## Sprint 2 — Security Intelligence Core (CLOSED ✅ 2026-06-12)
- [sprint-2-task-board.md](./sprint-2-task-board.md) — 11 tasks, agent assignments, tech stack, dependencies
- [s2-closeout-summary.md](./s2-closeout-summary.md) — final closeout state: 6 in-flight commits (3e241f6, a81f2a9, 9c4e99e, 2e85a86, 41420fe, 988783b) all on origin/main
- [sprint-2-closeout.md](./sprint-2-closeout.md) — SBOMPipelineAgent's view of the closeout
- [s3-backlog-state.md](./s3-backlog-state.md) — Sprint 3 backlog (S3.1 P0 = v2 SBOM cutover, 7 other tickets)
- [project-sprint2-vulnerability-intelligence.md](./project-sprint2-vulnerability-intelligence.md) — VulnerabilityIntelligenceAgent: S2.2 (vuln-intel :4008) + S2.3 (dep-intel :4009) + S2.8 hardening (validators, consensus, audit, LLM)
- Repo: https://github.com/fadhilfathi/ai-devsecops-command-center
- [sprint-1-status.md](./sprint-1-status.md) — Sprint 1 final status (232 files, 16,889 insertions, all 10 success criteria met)
- [sprint-1-retrospective.md](./sprint-1-retrospective.md) — PlatformArchitect retrospective: contributions, conventions locked, Sprint 2 hot list
- [sprint-1-task-board.md](./sprint-1-task-board.md) — sprint 1 task assignments

## Per-agent work
- [system-architecture-definition.md](./system-architecture-definition.md) — PlatformArchitect: system architecture
- [event-bus-design.md](./event-bus-design.md) — PlatformArchitect: event bus design
- [s2-runtime-observability.md](./s2-runtime-observability.md) — SREEngineer: S2.7 Python OTel, metrics, alerts, dashboard
- [s2-security-service-metrics.md](./s2-security-service-metrics.md) — FullstackEngineer: 6 proposed metrics for security-service :4003 proxy layer (S2.7 scope)
- [s2-security-service-metrics-wired.md](./s2-security-service-metrics-wired.md) — FullstackEngineer: 6 metrics wired in code; awaiting SRE cardinality lint
- [s2-shared-metrics-helper.md](./s2-shared-metrics-helper.md) — FullstackEngineer: `@aicc/observability` helper created; refactored metrics to use it; dropped `tenant_id_hash` per metrics-spec §5.1
- [s2-scan-topic-and-assetid.md](./s2-scan-topic-and-assetid.md) — FullstackEngineer → ComplianceOfficer: `SCAN_TOPIC` + `assetId` + `kind` added to topics.ts; 1 open question (introducedIn vs introducedAt)
- [s2-vuln-schema-handoff.md](./s2-vuln-schema-handoff.md) — FullstackEngineer → ComplianceOfficer: CloudEvents envelope + vulnerability shape + `kind`/`introducedAt` proposal (S2.9)
- [s2-gitops-wire-format-alignment.md](./s2-gitops-wire-format-alignment.md) — FullstackEngineer ↔ GitOpsManager: 3 gaps between security-service :4003 emit code and S2.10 NDJSON contract; holding code changes pending sign-off
- [s2-sbom-v2-spec-alignment.md](./s2-sbom-v2-spec-alignment.md) — FullstackEngineer ↔ SBOMPipelineAgent: Lead's v2 spec (URN bom-ref + prefix-string target) — code changes landed
- [s2-sbom-pipeline-v2-completion.md](./s2-sbom-pipeline-v2-completion.md) — S2.1 v2 service: missing `syft_wrapper.py` written, 12 test failures fixed, 69/69 pass (parked by Lead 2026-06-12 for Sprint 3 cutover)
- [s2-sbom-pipeline-v1-hotfix.md](./s2-sbom-pipeline-v1-hotfix.md) — S2.1 v1 service at `agents/roles/security/sbom-generator/`: 15 test failures + 1 startup crash fixed; S2.7/S2.10/S2.8 contract refinements applied; 73/73 pass
- [sprint-2-closeout.md](./sprint-2-closeout.md) — Sprint 2 (Security Intelligence Core) closed 2026-06-12: 11/11 main tasks, 37 commits, S3.1 (v2 cutover) is the Sprint 3 P0 owned by me
- [monitoring-architecture.md](./monitoring-architecture.md) — SREEngineer: monitoring, logging, metrics architecture
- [gitops-manager-sprint-1.md](./gitops-manager-sprint-1.md) — GitOpsManager: repo, CI/CD, contributor docs, ADRs 0005-0007

## Open items (cross-team, as of 2026-06-12 — Sprint 2 closeout)

| ID  | Item                                                                | Owner             | Status         | Waiting on                                          |
| --- | ------------------------------------------------------------------- | ----------------- | -------------- | --------------------------------------------------- |
| O-1 | **Sprint 2 kickoff** (Security Intelligence Core — Trivy/Syft, CVE ingestion, risk engine, security dashboard) | Lead              | ✅ KICKED OFF 2026-06-12 | —                                                  |
| O-2 | ~~FullstackEngineer 6-package split + Turborepo + Prisma + RS256 + port renumber~~ | — | SUPERSEDED by Sprint 2 mission (separate scope; revisit at end of Sprint 2) | — |
| O-3 | ~~GitOpsManager docs PR (gated on O-2)~~ | — | SUPERSEDED by Sprint 2 GitOps scope (auto-commit SBOM, vuln reports, SECURITY.md) | — |
| O-4 | SRE Jinja macro cleanup (small docs-only follow-up; not in Sprint 2 backend reshape) | SREEngineer | optional | SREEngineer |
| O-5 | **GitHub repo creation + push** | Lead | ✅ DONE 2026-06-12 — `fadhilfathi/ai-devsecops-command-center` live, 12 commits pushed | — |
| O-6 | **Sprint 2 closeout** (11/11 main tasks + 3 follow-ups + 3 in-flight spec-alignment commits) | Lead | ✅ CLOSED 2026-06-12 | — |
| O-7 | **Sprint 3 kickoff** (P0 = v2 SBOM cutover S3.1, +7 P1/P2 tickets) | Lead | 🟡 PLANNED 2026-06-15 | — |

## Cross-cutting
- [project-conventions.md](./project-conventions.md) — locked naming, layout, stack, ownership
- [feedback-coordination.md](./feedback-coordination.md) — lessons from Sprint 1 parallel-work coordination
- [observability-layout.md](./observability-layout.md) — dev/prod observability file layout, open items (Loki, runbook templating)
- [sprint-2-coordination.md](./sprint-2-coordination.md) — backend package split + Turborepo migration commitments
