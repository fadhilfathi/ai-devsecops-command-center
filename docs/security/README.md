# Security

> **Owner**: SecurityArchitect
> Operational security guidance for the platform: threat model, key
> management, network policy, and incident response.

## Folder layout

```
docs/security/
├── README.md                # this file
├── threat-model.md          # STRIDE-based threat model
├── hardening.md             # baseline hardening for prod
├── secrets.md               # how secrets are managed
├── network.md               # network policy and zero-trust notes
├── incident-response.md     # what to do when (not if) something happens
├── key-management.md        # key rotation, signing, etc.
└── hall-of-fame.md          # reporters we thank publicly
```

## See also

- [`/SECURITY.md`](../../SECURITY.md) — vulnerability disclosure
- [`/docs/architecture/security-model.md`](../architecture/security-model.md)
- [`/docs/compliance/`](../compliance/) — control mapping
