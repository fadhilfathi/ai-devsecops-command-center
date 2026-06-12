# Compliance

> **Owner**: ComplianceOfficer
> This folder is the home for control mappings, audit evidence, and
> the compliance posture of the platform itself.

## Folder layout

```
docs/compliance/
├── README.md           # this file
├── cis-v8/             # CIS Controls v8 mapping
├── nist-800-53/        # NIST 800-53 (Rev. 5) mapping
├── soc2/               # (future) SOC 2 evidence
├── iso-27001/          # (future) ISO 27001 mapping
├── evidence/           # signed evidence artifacts
└── audits/             # audit reports
```

## How compliance works in the platform

1. Every state-changing event in the system is mirrored to a
   `compliance.evidence.attached.v1` stream.
2. The `compliance` service consumes the mirror and applies control
   mappings (CIS / NIST / etc.) to produce per-control attestations.
3. Attestations are signed (HMAC chain) and stored in
   `docs/compliance/evidence/`.
4. A signed **attestation artifact** can be generated on demand for
   auditors.

See [`/docs/architecture/security-model.md`](../architecture/security-model.md)
and [`/docs/adr/0008-compliance-evidence-stream.md`](../adr/0008-compliance-evidence-stream.md).

## What lives here vs. the running system

| What                                            | Where                                  |
| ----------------------------------------------- | -------------------------------------- |
| Control **mappings** (the rules)                | This folder, plus the `compliance` DB  |
| Live **posture** (current pass/fail per control)| Grafana / `compliance` service API     |
| **Evidence** (raw + signed)                     | Object store; pointers in this folder  |
| **Audit reports** (generated artifacts)         | This folder                            |

## See also

- [`/docs/adr/0008-compliance-evidence-stream.md`](../adr/0008-compliance-evidence-stream.md)
- [`/docs/security/`](../security/) — operational security
- [`/docs/architecture/security-model.md`](../architecture/security-model.md)
