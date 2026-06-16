# @aicc/reporting-service

Sprint 4 — Reporting.

Generates the six canonical infrastructure reports and
exposes them in three formats (PDF, Markdown, JSON):

| Report                              | Endpoint                                          |
| ----------------------------------- | ------------------------------------------------- |
| Cluster Health Report               | GET /v1/reports/cluster-health                    |
| Infrastructure Risk Report          | GET /v1/reports/infrastructure-risk               |
| Runtime Security Report             | GET /v1/reports/runtime-security                  |
| Cost Optimization Report            | GET /v1/reports/cost-optimization                 |
| Topology Report                     | GET /v1/reports/topology                          |
| Executive Infrastructure Summary    | GET /v1/reports/executive-summary                 |

Each report is available in three formats via the `?format=`
query parameter:

- `json` (default) — the structured payload
- `md` — Markdown
- `pdf` — minimal PDF (text-only, Sprint 4); full visual PDF
  is scheduled for Sprint 5

All reports are tenant-scoped and can be filtered by
`clusterId` / `namespace` query parameters.

In Sprint 4 the report service calls the other Sprint 4
services over HTTP when their URLs are configured, and falls
back to the in-process fixture provider otherwise. This
allows the report service to run as a stand-alone process
with a single `pnpm dev` for development.
