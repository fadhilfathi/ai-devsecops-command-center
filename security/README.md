# `security/` — GitOps wire-format schemas

This directory holds the JSON Schema contracts for the security event
payloads shared across services (`sbom-pipeline`, `vuln-intel`,
`security-service`).

## Layout

```
security/
├── README.md            # this file
└── wire-format/          # JSON Schema source of truth for the wire payloads
    ├── sbom-generated.schema.json
    └── vulnerability-gitops-record.schema.json
```

## Wire-format schemas

- [`wire-format/sbom-generated.schema.json`](wire-format/sbom-generated.schema.json)
  — schema for the `security.sbom.generated.v1` event payload.
- [`wire-format/vulnerability-gitops-record.schema.json`](wire-format/vulnerability-gitops-record.schema.json)
  — schema for the per-finding `security.vulnerability.gitops-record.v1`
  record, projected from the richer `VulnerabilitySchema` in
  `backend/models/security/vulnerability.model.ts`.

Both schemas are validated against fixtures in
[`tests/contracts/`](../tests/contracts/), which is the authoritative
contract test suite — see that directory's `README.md` for how the
JSON Schema and the Zod runtime schema are kept in lockstep.
