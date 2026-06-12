# Runbooks

> Step-by-step operator procedures for the platform. If a procedure is
> tribal knowledge, it belongs here.

## Folder layout

```
docs/runbooks/
├── README.md                # this file
├── incident/                # what to do during an incident
├── recovery/                # restoring after a failure
├── upgrade/                 # upgrading services
├── data/                    # DB migrations, backups, restores
└── integration/             # rotating GitHub app keys, etc.
```

## Convention

- A runbook is a numbered procedure with **clear preconditions** and
  **verification steps**.
- Every runbook has an **owner team**.
- Every runbook is **tested** in a non-prod environment at least once
  per quarter.

## See also

- [`/docs/operations/`](../operations/) — day-to-day operations
- [`/docs/security/incident-response.md`](../security/incident-response.md)
