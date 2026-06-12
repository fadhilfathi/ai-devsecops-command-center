---
name: Sprint 2 Task Board
description: Sprint 2 Security Intelligence Core task board
type: project
---

# Sprint 2 Task Board

**Sprint:** 2 — Security Intelligence Core
**Started:** 2026-06-12
**Status:** IN PROGRESS

## Tasks (11 total)

| ID | Subject | Owner | Status | Blocked By |
|---|---|---|---|---|
| 019ebbbb-8769-7872-83b0-e3302447c172 | S2.1: SBOM Pipeline System (Syft-wrapped Python service) | SBOMPipelineAgent | in_progress | S2.4 (models) |
| 019ebbbb-876c-7033-84ae-1cfb00a357d9 | S2.2: Vulnerability Engine (CVE ingestion + scoring) | VulnerabilityIntelligenceAgent | in_progress | S2.4 (models) |
| 019ebbbb-876f-7f53-ada1-d0e6073d3700 | S2.3: Dependency Intelligence Layer | VulnerabilityIntelligenceAgent | in_progress | S2.1, S2.2, S2.4 |
| 019ebbbb-8771-7c72-b93e-c9a41b1fc191 | S2.4: Security Data Models (shared types) | FullstackEngineer | pending | - |
| 019ebbbb-8773-7fd0-9870-fddcaf6b03e6 | S2.5: Security API Layer (5 endpoints) | FullstackEngineer | pending | S2.1, S2.2, S2.3, S2.4 |
| 019ebbbb-8775-7cc0-adc4-ba6fecdad1df | S2.6: Security Dashboard UI (5 visualizations) | UIUXEngineer | pending | S2.5 |
| 019ebbbb-8777-76e1-9120-9dd56688637e | S2.7: Runtime Observability for Security Stack | SREEngineer | pending | - |
| 019ebbbb-8779-7963-8b0a-447d57081dc3 | S2.8: Threat Model Validation for Security Stack | SecurityArchitect | pending | - |
| 019ebbbb-877b-7101-8744-8ae354ee76c4 | S2.9: Compliance Auto-mapping (CVEs to controls) | ComplianceOfficer | pending | - |
| 019ebbbb-877e-71c0-88d5-1dff3f2739fe | S2.10: GitOps Security Automation | GitOpsManager | pending | S2.1, S2.2, S2.5 |
| 019ebbbb-8780-7703-9a17-457fc622d0fc | S2.11: End-to-End Validation + First Security Report | Leader | pending | S2.6 |

## Agent Slot IDs (Sprint 2)

| Agent | Slot |
|---|---|
| VulnerabilityIntelligenceAgent | 019ebbbb-8761-7f50-b26a-4d51419a60a8 |
| SBOMPipelineAgent | 019ebbbb-8766-7452-9226-5a9a20b7539c |
| SecurityArchitect | 019ebae2-9de4-7223-9920-60866bc88d45 |
| PlatformArchitect | 019ebae2-9df9-7db0-a45b-c36d235b811e |
| SREEngineer | 019ebae2-9e02-7e01-9b2b-451eb0d20f59 |
| ComplianceOfficer | 019ebae2-9e0c-7981-ba99-225c9c32226d |
| UIUXEngineer | 019ebae2-9e15-75b3-9d62-0aca5b05788e |
| FullstackEngineer | 019ebae2-9e1c-7273-a8ce-e74cc95e5b0a |
| GitOpsManager | 019ebae2-9e25-7970-952c-4236216ff0d5 |
| Leader | 019ebae0-7788-7d22-beea-701c1d0d685a |

## Tech Stack (Sprint 2)

### New Python services
- **sbom-pipeline-service** (port 4007) — wraps Syft CLI, FastAPI + uvicorn
- **vuln-intel-service** (port 4008) — NVD/GHSA/OSV + EPSS + CISA KEV, FastAPI
- **dependency-intel-service** (port 4009) — NetworkX graph + risk propagation, FastAPI

### Key dependencies
- Syft (SBOM generation, all input types, CycloneDX + SPDX output)
- EPSS API (exploit prediction scoring)
- CISA KEV (known exploited vulnerabilities)
- NetworkX (graph algorithms)
- Pydantic v2 (validation)
- structlog (JSON logging)
- OpenTelemetry (distributed tracing)
- prometheus_client (metrics)

### Extended Node.js services
- **security-service** (port 4003) — 5 new endpoints added
- **compliance-service** (port 4005) — auto-mapping + POA&M lifecycle

### Extended frontend
- 5 new visualizations: SBOM Viewer, Vuln Timeline, Risk Heatmap, Dependency Graph, Security Score
- New routes: /graph/:sbom_id
- New deps: d3-force or react-flow for graph viz
