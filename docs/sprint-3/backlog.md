# Sprint 3 Backlog

> **Sprint window:** 2026-06-15 → 2026-06-26 (provisional)
> **Status:** DRAFT — pending Lead approval
> **Sprint goal:** Production hardening of the Security Intelligence Core
> and completion of the v2 SBOM pipeline cutover.

## Tickets

### S3.1 — Complete v2 SBOM pipeline service and cut over from v1

- **Owner:** SBOMPipelineAgent
- **Reviewer:** Lead (Architect)
- **Priority:** P0
- **Effort:** 3–5 days
- **Source draft:** `docs/drafts/sbom-pipeline-service-v2/`
- **Acceptance criteria:**
  1. `src/sbom_pipeline/syft_wrapper.py` exists and matches the contract
     defined by `tests/test_syft_wrapper.py` and the imports in
     `parsers.py` / `api.py` / `cli.py`.
  2. `pytest` is green for `test_syft_wrapper.py`, `test_parsers.py`,
     `test_analyzer.py`, `test_api.py`.
  3. Integration test against a live Syft `1.6.0` binary passes for
     all four source prefixes (`docker:`, `git:`, `fs:`, `lockfile:`).
  4. TypeScript models (`backend/models/security/sbom.model.ts`) and
     route handlers (`backend/services/security/src/routes/sbom-pipeline.ts`)
     are on the v2 wire format.
  5. 1% dark-launch traffic mirrored from the security-service to v2
     for 7 days with byte-for-byte CycloneDX 1.5 output match and
     p99 latency within the v1 SLO.
  6. v1 (`agents/roles/security/sbom-generator/`) is removed from
     the repo and the architecture docs.
  7. `docker-compose.yml`, k8s manifests, and CI workflows are
     updated to point at v2.
  8. `CHANGELOG.md` records the v1 → v2 cutover as a Sprint 3 entry.

### S3.2 — Live Trivy + Dependency-Track integration

- **Owner:** VulnerabilityIntelligenceAgent
- **Reviewer:** SecurityArchitect
- **Priority:** P1
- **Effort:** 3 days
- **Source:** Sprint 1 → Sprint 2 retro
- **Acceptance criteria:**
  1. Trivy CLI wrapper follows the same architectural pattern as the
     Syft wrapper (bus, store, telemetry, OTel).
  2. Trivy findings are correlated with Syft SBOM components by
     `purl`.
  3. Dependency-Track project is created per tenant, fed by the
     `security.sbom.generated.v1` topic.
  4. New `security.sbom.vulnerability.correlated.v1` topic carries
     the merged SBOM + Trivy finding view.
  5. Dashboard gains a "Live Trivy Scan" view that auto-refreshes.

### S3.3 — Agent runtime v1 (event-driven loop + restart policies)

- **Owner:** PlatformArchitect
- **Reviewer:** Lead
- **Priority:** P1
- **Effort:** 4 days
- **Source:** `docs/architecture/agent-topology.md` § "Runtime"
- **Acceptance criteria:**
  1. Agent supervisor process (Python) that subscribes to
     `agent.{role}.{action}.v1` and dispatches to the role's
     `agent.py`.
  2. Restart policy: exponential backoff (1s, 2s, 4s, 8s, 16s, 30s
     cap), max 5 restarts in 60s before crash-looping the supervisor.
  3. Health check: `/healthz` reports last successful message
     timestamp; stale > 5m = unhealthy.
  4. The three security agents (SBOM, VulnIntel, DepIntel) and the
     compliance agent run end-to-end under the supervisor.
  5. Helm chart for the supervisor in `infra/helm/aionrs-supervisor/`.

### S3.4 — WebSocket real-time channel for the security dashboard

- **Owner:** FullstackEngineer
- **Reviewer:** UIUXEngineer
- **Priority:** P2
- **Effort:** 2 days
- **Source:** S2.6 retro — "live data, not polling"
- **Acceptance criteria:**
  1. Fastify WebSocket route at `/ws/security` on the
     security-service.
  2. Subscribes to `security.{sbom,vulnerability,risk}.*.v1` topics
     and forwards to connected clients.
  3. Frontend `useSecurityStream()` React hook with reconnection
     logic.
  4. `Vulnerabilities`, `SBOM`, and `RiskHeatmap` pages switch to
     stream-based updates (no more `setInterval` polling).
  5. Backpressure: drop oldest message if client lag > 10s.

### S3.5 — Helm chart for the AionRs security stack

- **Owner:** SREEngineer
- **Reviewer:** PlatformArchitect
- **Priority:** P1
- **Effort:** 3 days
- **Source:** Sprint 2 retro
- **Acceptance criteria:**
  1. `infra/helm/aionrs/` chart with subcharts for:
     `security-service`, `sbom-pipeline-service` (or v2),
     `vuln-intel`, `dependency-intel`, `compliance-service`.
  2. Values for: replica count, resource limits, ingress, secrets,
     ConfigMap for the devsecops_* metric labels.
  3. PodDisruptionBudget, HorizontalPodAutoscaler, NetworkPolicy
     for each service.
  4. Loki/Prometheus/Tempo sidecar wiring via annotations.

### S3.6 — Terraform landing zone for the security stack

- **Owner:** SREEngineer
- **Reviewer:** Lead
- **Priority:** P2
- **Effort:** 3 days
- **Source:** Sprint 2 retro
- **Acceptance criteria:**
  1. `infra/terraform/` modules for VPC, EKS/AKS, RDS, ElastiCache
     (Redis), S3, KMS, IAM.
  2. Per-tenant namespace pattern via Terraform workspaces.
  3. Remote state in S3 + DynamoDB lock.
  4. `terraform plan` is checked in CI on every PR.

### S3.7 — Compliance evidence auto-collection (CIS v8 / NIST 800-53)

- **Owner:** ComplianceOfficer
- **Reviewer:** SecurityArchitect
- **Priority:** P1
- **Effort:** 4 days
- **Source:** `docs/compliance/evidence-collection.md` § "Automated
  evidence"
- **Acceptance criteria:**
  1. Scheduled jobs (cron-style) for each of the 18 CIS v8 controls
     and 12 NIST 800-53 controls with "automated" status in
     `docs/compliance/control-matrix.md`.
  2. Each job emits a signed evidence artifact to
     `security.evidence.{control_id}.collected.v1`.
  3. POA&M items are auto-created for failed controls with a
     14-day SLA.
  4. Evidence dashboard in the Compliance page shows real-time
     status with last-collected timestamps.

### S3.8 — Risk score explainability (SHAP-style feature attributions)

- **Owner:** DataScientist (to be hired)
- **Reviewer:** VulnerabilityIntelligenceAgent
- **Priority:** P3
- **Effort:** 5 days
- **Source:** S2.4 retro
- **Acceptance criteria:**
  1. For every risk score, a list of top-K feature contributions is
     available (e.g., "EPSS percentile: +0.34", "KEV: +0.20",
     "transitive depth: +0.12").
  2. `risk_explainability.json` is attached to the
     `security.risk.calculated.v1` event payload.
  3. Frontend `RiskHeatmap` shows a tooltip with the top-3
     contributions on hover.

## Sprint 3 ceremonies

- **Sprint planning:** 2026-06-15 (1h, all agents)
- **Daily standup:** async via `team_send_message` to the Lead
- **Mid-sprint check-in:** 2026-06-19 (30m, blockers only)
- **Sprint review:** 2026-06-26 (1h, all agents + demo to user)
- **Sprint retro:** 2026-06-26 (30m, after review)

## Success criteria

- All P0 and P1 tickets complete
- S2.11 E2E validation report is referenced in the v2 cutover
- Architecture docs are updated for every shipped change
- `CHANGELOG.md` has a complete Sprint 3 entry
- No new `devsecops_*` metrics introduced without a SLO target
- All Sprint 3 commits are signed and pass CI
