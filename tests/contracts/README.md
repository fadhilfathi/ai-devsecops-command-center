# Contract tests (S2.10 + O-3.7)

Cross-team contract tests that lock the GitOps wire format so producers
and consumers cannot drift. **Owner: GitOpsManager.** Consumers are
vuln-intel :4008 (producer of the rich event) and security-service
:4003 (projector of the GitOps record); producers are the `.github/workflows/`
automation (consumer of the NDJSON); `compliance-service` is a
downstream consumer of the GitOps record (for POA&M auto-mapping per
O-3.7 § "Downstream routing").

## Why this directory exists

The security GitOps contract is documented in two places:

1. **JSON Schema (canonical)** — `security/wire-format/*.schema.json`
2. **Zod schema (TS runtime)** — `backend/models/security/vulnerability.model.ts::VulnerabilityGitOpsRecordSchema`
   (FullstackEngineer-owned, lives next to the producer code)

The two MUST stay in lockstep. If they drift, a producer passing Zod
validation at runtime will fail JSON Schema validation at the receiver
(or vice versa), and S2.10 will silently drop records.

This directory contains the **authoritative spec tests** for the
contract. They validate against the JSON Schema, the O-3.7 spec
(`security/README.md` § "auto_actionable gate"), and the 4-condition
formula locked in O-3.7. The Zod schema in `backend/models/security/`
is expected to mirror these tests 1:1; if it doesn't, **the Zod
schema is wrong, not these tests.**

## Layout

```
contracts/
├── README.md
├── package.json
├── vulnerability-gitops-record.contract.spec.ts
├── sbom-generated.contract.spec.ts
└── fixtures/
    ├── vulnerability-gitops-record.examples.json
    └── sbom-generated.examples.json
```

## How the test suite is structured

Each `*.contract.spec.ts` file is a [vitest](https://vitest.dev/) spec
that:

1. Loads the JSON Schema from `security/wire-format/*.schema.json`.
2. Loads the positive/negative examples from `fixtures/*.examples.json`.
3. Validates each positive example against the JSON Schema — should PASS.
4. Validates each negative example against the JSON Schema — should FAIL.
5. Cross-validates the 4-condition `auto_actionable` formula against
   a battery of truth-table inputs.

## Running

```bash
cd tests/contracts
npm install
npm test
```

The tests are hermetic — they do NOT require docker-compose, the event
bus, or any backend service running. They run in <500ms on a laptop.

## When to update

The contract tests MUST be updated when:

- A new field is added to the JSON Schema (e.g. O-3.7 added 5 fields
  to the vuln record and 2 fields to the SBOM event).
- An enum value is added or removed.
- The `auto_actionable` gate formula is refined (O-3.6 was 4 conditions;
  O-3.7 added the EPSS branch to condition 2; a future O-3.8 might
  add a 5th condition).
- A regex is loosened or tightened (e.g. `sbom_fingerprint` regex
  gained `sha512 | blake3` support in O-3.7).

## Sprint 2 / O-3.7 status

- `vulnerability-gitops-record.contract.spec.ts`: covers the **O-3.7 4-condition formula**, 17 required fields, all enums, all regexes, and the new `consensus_sources` field.
- `sbom-generated.contract.spec.ts`: covers the O-3.7 13-required-field schema, the new `sbom_fingerprint_algorithm` and `sbom_fingerprint_format` enums, the loosened `sbom_fingerprint` regex (sha256 | sha512 | blake3).
- **Known drift:** the FullstackEngineer-owned Zod schema `VulnerabilityGitOpsRecordSchema` in `backend/models/security/vulnerability.model.ts` is at the O-3.5 3-condition state. FullstackEngineer plans to align it with O-3.7 in Sprint 2.1. The contract tests fail on the O-3.5 Zod schema by design; they will pass once Sprint 2.1 lands.

## Cross-references

- `docs/security/s2-test-plan.md` §3.6 — the Sprint 2.8 test plan cases
  (DC-01..DC-04, OWASP ASVS / NIST SSDF mapped). When the GitOps
  contract surface changes, port the affected test cases here so the
  trail `test-case → contract fixture → Sprint 2 deliverable` is
  auditable. The DC-04 (T-09 canary emission) case in particular
  will be re-anchored against the O-3.7 `canary_test_run_id` contract
  in Sprint 3. **Owner of the S2.8 test plan: SecurityArchitect.**
  Co-review offer standing for S3 (when FullstackEngineer ports the
  S2.8 test plan cases into the contract suite, SecurityArchitect
  will co-sign the canary + mapping-engine cases).

## See also

- `security/README.md` — operator-facing mirror of the wire format
- `security/wire-format/*.schema.json` — JSON Schema source of truth
- `docs/architecture/event-bus.md` — Sprint 2 contract addendum
- `docs/runbooks/security-automation.md` — operator runbook
