# Auth service (`@aicc/auth-service`)

> Identity, sessions, RBAC, and multi-tenant context.

**Port**: 3001

## Responsibilities

- Issue, validate, and revoke **JWT access tokens** (15 min) and
  **rotating refresh tokens** (30 days).
- Maintain the **user directory** per tenant.
- Maintain **roles, scopes, and tenant memberships**.
- Serve `/.well-known/openid-configuration` and `/jwks.json` for
  downstream services that need to verify tokens locally.
- Mirror auth events to the **audit log**.

## Out of scope

- UI / login pages (the SPA does that against `/oauth/*`).
- Long-term SSO identity storage (delegated to OIDC provider).
- Password policy enforcement (delegated to OIDC provider or the local
  fallback flow).

## API (high level)

- `POST   /auth/login` — username / password (local fallback)
- `POST   /auth/refresh` — exchange a refresh token
- `POST   /auth/logout` — invalidate the current session
- `GET    /auth/me` — who am I
- `GET    /auth/users` — list users (admin)
- `POST   /auth/users` — create a user (admin)
- `PATCH  /auth/users/:id` — update roles / scopes
- `DELETE /auth/users/:id` — soft-delete a user
- `GET    /auth/tenants` — list tenants (super_admin)
- `POST   /auth/tenants` — create a tenant (super_admin)
- `GET    /.well-known/jwks.json` — public keys
- `GET    /healthz` — liveness
- `GET    /readyz` — readiness
- `GET    /metrics` — Prometheus

## Events

- Consumes: nothing (this service is upstream of the bus)
- Produces: `system.user.created.v1`, `system.user.deleted.v1`,
  `system.user.role-changed.v1`, `system.session.revoked.v1`

## See also

- [`/docs/architecture/security-model.md`](../../docs/architecture/security-model.md)
- [`/docs/adr/0006-jwt-auth-model.md`](../../docs/adr/0006-jwt-auth-model.md)
