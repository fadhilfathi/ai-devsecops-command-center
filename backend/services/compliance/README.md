# Compliance service (`@aicc/compliance-service`)

> Control mapping, evidence collection, and audit-ready attestations.

**Port**: 3005

## Responsibilities

- Maintain the **control library** (CIS v8, NIST 800-53 Rev. 5, …).
- Consume the **evidence stream** and apply the mapping rules to produce
  per-control attestations.
- Expose a **posture API**: "what is our current pass/fail per
  control, per tenant?".
- Generate a signed **attestation artifact** on demand for auditors.
- Mirror every attestation to the **audit log** (HMAC-chained).

## API (high level)

- `GET    /controls` — list controls (filter by framework)
- `GET    /controls/:id` — get a control's definition
- `GET    /posture` — current posture per framework
- `GET    /posture/:framework` — posture for one framework
- `GET    /attestations/:id` — get an attestation
- `POST   /attestations` — generate a fresh attestation artifact
- `GET    /evidence` — list raw evidence (filter by control, asset, date)
- `GET    /evidence/:id` — get a single piece of evidence

## Events

- Consumes: the mirrored evidence stream
- Produces: `compliance.control.mapped.v1`,
  `compliance.evidence.attached.v1`,
  `compliance.attestation.built.v1`

## See also

- [`/docs/compliance/`](../../docs/compliance/) — control files
- [`/docs/adr/0008-compliance-evidence-stream.md`](../../docs/adr/0008-compliance-evidence-stream.md)
