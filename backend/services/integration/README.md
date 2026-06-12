# Integration service (`@aicc/integration-service`)

> External system adapters. The **only** service that talks to
> third-party APIs.

**Port**: 3006

## Responsibilities

- Ingest **webhooks** (GitHub, GitLab, scanners, etc.) and normalize
  them into internal events.
- Push **outbound notifications** (PR comments, Jira tickets, Slack
  messages).
- Manage **credentials** for third-party systems (never stored in
  environment variables in prod).
- Run **scheduled sync** jobs (e.g. nightly SBOM pull).

## Why a single service?

- One **blast radius** for outbound network calls.
- One **credential store**.
- One **rate limit** budget per provider.
- One **observability** pane for "what are we sending out?".

## API (high level)

- `POST   /webhooks/github` — GitHub webhook receiver (HMAC-verified)
- `POST   /webhooks/gitlab` — GitLab webhook receiver
- `POST   /webhooks/generic` — generic webhook receiver
- `GET    /integrations` — list configured integrations
- `POST   /integrations` — add an integration (admin)
- `PATCH  /integrations/:id` — update / disable
- `POST   /integrations/:id/test` — test credentials and reachability
- `GET    /integrations/:id/logs` — recent outbound calls

## Events

- Consumes: outbound events from any service
- Produces: `integration.github.pr.opened.v1`, etc. (normalized inbound)

## See also

- [`/docs/security/secrets.md`](../../docs/security/secrets.md)
