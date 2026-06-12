# Incident service (`@aicc/incident-service`)

> Incident lifecycle, correlation, response playbooks, and postmortems.

**Port**: 3004

## Responsibilities

- Open, classify, escalate, and resolve **incidents**.
- **Correlate** incoming findings with prior context (asset history,
  recent changes, KEV lists).
- Run **playbooks**: structured, declarative response flows that may
  invoke tools, agents, or human approvals.
- Produce a **postmortem draft** when an incident resolves.
- Surface live updates to the **Dashboard** over WebSocket.

## API (high level)

- `GET    /incidents` — list incidents (filter by sev, status, assignee, env)
- `POST   /incidents` — manually open an incident
- `GET    /incidents/:id` — get an incident
- `PATCH  /incidents/:id` — update (assign, reclassify, close)
- `POST   /incidents/:id/playbook` — run a playbook
- `GET    /incidents/:id/timeline` — get the full incident timeline
- `GET    /playbooks` — list registered playbooks
- `POST   /playbooks` — define a new playbook (admin)
- `GET    /postmortems/:id` — get a generated postmortem

## Events

- Consumes: `security.vulnerability.detected.v1`,
  `security.secret.found.v1`, `compliance.evidence.attached.v1`, …
- Produces: `incident.incident.opened.v1`,
  `incident.incident.classified.v1`,
  `incident.incident.resolved.v1`,
  `incident.postmortem.drafted.v1`

## See also

- [`/docs/runbooks/incident/`](../../docs/runbooks/incident/) — human
  playbooks for major incident types
