# Frontend service modules (legacy)

Service modules in the new AionUi live under
[`frontend/src/lib/services/`](../../lib/services/). This directory is
preserved for legacy imports during the migration window (Sprint 2).

Service modules wrap the REST API and expose typed hooks:

- `assets.service.ts` — list, get, sync
- `vulnerabilities.service.ts` — list, triage, assign, close
- `incidents.service.ts` — list, get, create note, escalate
- `sbom.service.ts` — get, export, diff
- `compliance.service.ts` — framework, control, evidence
- `integrations.service.ts` — list, test, sync
- `agents.service.ts` — list, get, dispatch
