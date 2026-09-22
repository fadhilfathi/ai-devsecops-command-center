# 0015 — Infrastructure findings mapped to CIS/NIST via the existing rules engine

Status: accepted
Date: 2026-09-23

## Context

`runtime-security-service` (9 rules, `AICC-RT-001..009`) and
`k8s-health-service` (health-issue kinds: `crash_loop_back_off`,
`oom_killed`, `node_pressure`, etc.) detected findings but never fed the
Compliance service — only vulnerability scans (`scan.completed`) drove
control mapping, POA&M creation, and evidence attachment via
`control-mapper/` + `evidence-attacher.ts`. Building a second mapping
engine for infrastructure findings would duplicate the predicate DSL,
the rules file, the POA&M dedup logic, and the evidence pipeline for no
reason — the shapes only differ in a handful of fields.

## Decision

- **Generalise `MappingInput`, don't fork it.** Added an optional
  `subjectKind: 'vulnerability' | 'runtime_risk' | 'health_issue'`
  discriminator (default `'vulnerability'`) plus `ruleId`,
  `resourceKind`, `namespace`, `clusterId`, `workloadName`. Every
  existing caller that never sets `subjectKind` keeps matching
  vulnerability-shaped inputs exactly as before — proven by the
  pre-existing `control-mapper.test.ts` suite passing unchanged.
- **Existing vulnerability rules gated by `subject_kind_is: vulnerability`.**
  The two "catch-all" NIST rules (`SI-2`, `RA-5`) match on `{ type:
'always' }`; without a guard they'd also match every infrastructure
  finding. Wrapped all six Sprint-2 rules in
  `and: [{ subject_kind_is: 'vulnerability' }, <original predicate>]` —
  behaviourally identical for vulnerability inputs (the field defaults
  to `'vulnerability'`), and infrastructure findings can no longer leak
  into vulnerability-only controls.
- **New predicates, not a new engine.** `subject_kind_is`,
  `rule_id_in`, `resource_kind_is` — three more cases in
  `predicates.ts`'s existing switch. Health issues have no `ruleId`
  field on their own model; the listener stores the `HealthIssueKind`
  string (`'crash_loop_back_off'`, ...) in `MappingInput.ruleId` so
  `rule_id_in` works uniformly for both runtime risks and health
  issues.
- **New rules live in the same `mapping-rules.json`.** 16 new entries
  covering the 9 runtime-security rule ids and the 8 health-issue kinds
  against the CIS v8 / NIST 800-53 control ids the docs in
  `docs/compliance/` actually define (no invented control numbers).
- **Producers publish one batched event per request, not one per
  finding.** `EventTypes.RUNTIME_RISK_DETECTED` /
  `CLUSTER_HEALTH_ISSUE_DETECTED` now carry a `findings[]` array.
  `runtime-security-service`'s `POST /scan` and `k8s-health-service`'s
  `GET /health/issues` fire the publish without awaiting it (`void
bus.publish(...).catch(...)`) so it never blocks the response; a
  publish failure is logged, never fails the request.
- **Evidence = the finding JSON, reusing `EvidenceAttacher`.** Added
  `attachInfrastructureFinding()` alongside the existing `attach()` —
  same mapping engine, same `PoamService.createFromTuple` dedup, same
  `emitControlViolated`/`emitEvidenceAttached` private helpers, same
  in-memory blob store. It differs from `attach()` only in not having
  an SBOM/report pair to persist; the finding object itself is the
  evidence body. A new `infrastructure-listener.ts` (modelled 1:1 on
  `scan-listener.ts`) subscribes both topics and normalizes the payload
  into a `MappingInput` before calling it.

## Consequences

- Zero new services, zero new persistence, zero new dependencies. The
  entire feature is: 2 event types, ~16 rule entries, 3 predicates, one
  new `EvidenceAttacher` method, one new listener, two `bus.publish`
  call sites.
- Idempotency does **not** fully match the vulnerability flow: unlike
  `scan.completed`, `k8s-health-service` republishes every open issue on
  every `GET /v1/health/issues` poll, so the same finding is redelivered
  far more often than a scan result ever is. POA&M creation dedups on
  `(tenantId, controlId, vulnId)`, same as the vulnerability flow.
  Evidence, however, needed its own dedup: `EvidenceRepository.findByRef`
  looks up an existing row by `(tenantId, controlId, ref)` before
  inserting, and `attachInfrastructureFinding` skips the insert (and the
  `compliance.evidence.attached` event) on a repeat delivery — the blob
  ref is deterministic per finding id, so redelivery always resolves to
  the same ref.

## Deferred

- **Control-scoring weights.** Every matched rule currently contributes
  the boolean `'fail'` `ControlMapping.contributes` the vulnerability
  flow already used; no weighting of runtime-risk severity vs.
  vulnerability severity in an aggregate compliance score.
- **Drift / attestation.** No re-check that a finding has been
  remediated (the runtime-security/k8s-health scan is snapshot-based;
  closing the POA&M item is still a manual/API action, same as the
  vulnerability flow).
- **`GET /v1/health/issues` publishing on every read** is a
  `ponytail`-flavoured simplification — there's no dedicated "scan"
  action on `k8s-health-service` today. Batching every issue into one
  event per request and not awaiting the publish keeps this cheap, and
  evidence dedup (by blob ref) absorbs the redelivery; still, add a
  proper scan endpoint (mirroring runtime-security's `POST /scan`) or a
  debounce window if the read-path publish volume becomes a problem.
