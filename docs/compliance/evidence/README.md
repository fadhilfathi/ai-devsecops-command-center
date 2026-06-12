# Evidence Collection — Operational Artefacts

This directory is the landing zone for **operational evidence
artefacts** produced by the platform's continuous control monitoring
(CCM) pipeline. See
[`../evidence-collection.md`](../evidence-collection.md) for the
methodology and lifecycle.

## Layout

```
evidence/
├── ce/                  # Configuration evidence (CE) snapshots
│   ├── 2026/
│   │   ├── 06/
│   │   │   ├── auth-config-2026-06-12T00.json
│   │   │   ├── k8s-baseline-2026-06-12T00.json
│   │   │   └── ...
│   │   └── ...
│   └── ...
├── ae/                  # Activity evidence (AE) reference indices
│   ├── audit-log-pointer-2026-06-12.json
│   └── ...
├── at/                  # Attestation evidence (AT) signed docs
│   ├── 2026-Q2-security-attestation.json
│   └── ...
└── in/                  # Inherited evidence (IN) references
    ├── cloud-provider-soc2-2025.json
    └── ...
```

## Conventions

- Filenames include a timestamp (RFC 3339) and a content hash.
- Each file is the **output** of an evidence source as registered in
  §2 of [`../evidence-collection.md`](../evidence-collection.md).
- Files are immutable once written; corrections are new files with a
  `superseded_by` pointer.
- Retention: matches the audit log retention schedule (13 months hot
  + 7 years warm/cold).
