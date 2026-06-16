# @aicc/runtime-security-service

Sprint 4 — Runtime Security Intelligence.

Detects Kubernetes runtime-security risks across the tenant's
clusters:

- Privileged containers
- hostPath volume mounts
- root user (uid 0) execution
- dangerous Linux capabilities (`NET_RAW`, `SYS_ADMIN`, ...)
- weak / missing SecurityContext
- risky ServiceAccount usage (default SA + automount token)
- risky RBAC bindings (cluster-admin to a workload SA)

Produces a `RuntimeSecurityReport` per cluster / per tenant
with risk level (`critical` / `high` / `medium` / `low`) and a
0..100 score (higher = safer).

## Endpoints

| Method | Path                                          | Description                       |
| ------ | --------------------------------------------- | --------------------------------- |
| GET    | `/v1/runtime-security/risks`                  | Per-finding risk list             |
| GET    | `/v1/runtime-security/risks/:id`              | Single finding detail             |
| POST   | `/v1/runtime-security/scan`                   | Trigger a re-scan (idempotent)    |
| GET    | `/v1/runtime-security/report`                 | Tenant-wide rollup report         |
| GET    | `/v1/runtime-security/report/cluster/:id`     | Per-cluster rollup report         |
| GET    | `/v1/runtime-security/rules`                  | List active rules                 |
