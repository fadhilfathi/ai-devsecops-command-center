# Security service (`@aicc/security-service`)

> Assets, vulnerabilities, and SBOMs. The system of record for "what
> code is running, where, and what's wrong with it".

**Port**: 3003

## Responsibilities

- Maintain the **asset inventory** (repos, images, services, IaC).
- Ingest **vulnerability findings** from scanners, agents, and humans.
- Maintain the **SBOM** for every asset.
- Deduplicate and correlate findings.
- Produce `security.vulnerability.detected.v1`,
  `security.sbom.generated.v1`, `security.secret.found.v1`.

## API (high level)

- `GET    /assets` — list assets (filter by type, env, owner, tag)
- `POST   /assets` — create / register an asset
- `GET    /assets/:id` — get an asset, including its SBOM
- `GET    /assets/:id/sbom` — get the SBOM (CycloneDX 1.5 JSON)
- `GET    /vulnerabilities` — list findings (filter by sev, status, asset)
- `POST   /vulnerabilities` — ingest a finding
- `PATCH  /vulnerabilities/:id` — update status (open, triaged, suppressed, fixed)
- `GET    /vulnerabilities/:id/timeline` — get the full lifecycle

## Events

- Consumes: `integration.github.pr.opened.v1`, etc.
- Produces: `security.vulnerability.detected.v1`,
  `security.sbom.generated.v1`, `security.secret.found.v1`,
  `security.license.flagged.v1`

## See also

- [`/docs/architecture/event-bus.md`](../../docs/architecture/event-bus.md)
- [`/docs/compliance/`](../../docs/compliance/) — for control mapping
