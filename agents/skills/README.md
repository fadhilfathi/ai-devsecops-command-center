# Reusable Agent Skills

Skills are the building blocks agents compose. A skill is a typed function that
takes a validated input and returns a validated output, with no side effects on
the bus.

## Examples (planned)

- `fetch_sbom(commit_sha) -> SBOM`
- `lookup_cve(package, version) -> [Vulnerability]`
- `create_github_pr_comment(pr, body)`
- `attach_evidence(control_id, artifact_uri)`
- `send_slack_message(channel, body)`
- `open_incident(severity, summary)`

Skills are versioned independently from agents and can be reused across
multiple agents.

## Conventions

- One skill per module.
- Inputs and outputs are Pydantic models.
- Skills emit OpenTelemetry spans.
- Skills never call the bus directly — the agent owns bus interactions.
