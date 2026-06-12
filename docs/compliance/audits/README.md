# Internal & External Audits

This directory is the **audit binder** — a structured location for
audit reports, evidence bundles, and correspondence.

## Layout

```
audits/
├── internal/
│   ├── 2026/
│   │   ├── Q2-self-assessment.md
│   │   ├── Q2-self-assessment-evidence/
│   │   └── ...
│   └── ...
├── external/
│   ├── soc2/
│   │   ├── 2026-soc2-type1-report.pdf
│   │   ├── 2026-soc2-type1-evidence/
│   │   └── ...
│   ├── iso27001/
│   │   └── ...
│   └── pen-test/
│       ├── 2026-external-pentest-report.pdf
│       └── ...
├── customer-requests/
│   ├── request-2026-001-bundle.json
│   ├── request-2026-001-evidence/
│   └── ...
└── correspondence/
    ├── 2026-06-12-federal-prospect-oscal.md
    └── ...
```

## Naming

- Internal: `YYYY-Q[1-4]-<scope>.md`.
- External SOC 2: `YYYY-soc2-type[N]-report.pdf`.
- External pen-test: `YYYY-{internal,external}-pentest-report.pdf`.
- Customer request: `request-YYYY-NNN-<customer-slug>.json`.

## Retention

- Internal: 7 years.
- External: 7 years from report date, or per contract.
- Customer: 7 years from delivery.

## Access

- `internal/` and `external/`: ComplianceOfficer + SecurityArchitect.
- `customer-requests/`: ComplianceOfficer + assigned owner.
- `correspondence/`: ComplianceOfficer only.
