---
title: Evidence Collection Methodology
owner: ComplianceOfficer
status: draft
version: 0.1.0
last_updated: 2026-06-12
related:
  - ./audit-logging.md
  - ./compliance-matrix.md
  - ./nist-800-53.md
  - ./cis-controls-v8.md
---

# Evidence Collection Methodology

This document defines how the AI-DevSecOps Command Center **collects,
stores, validates, and exposes evidence** that a control is operating
effectively. It is the bridge between the framework mappings
([`nist-800-53.md`](./nist-800-53.md), [`cis-controls-v8.md`](./cis-controls-v8.md))
and the audit log ([`audit-logging.md`](./audit-logging.md)).

The platform's compliance posture rests on the principle that
**evidence must be produced by automated systems, not humans filling
out spreadsheets**. Every control in the framework mappings has at
least one *evidence source* — typically a system that emits a
machine-checkable artefact. A control without an evidence source is
considered *Not Implemented* regardless of intent.

## 1. Evidence types

The platform recognizes four evidence types. A single control may rely
on multiple types.

### 1.1 Configuration evidence (CE)

A snapshot of a system's configuration at a point in time, suitable
for diffing against a baseline.

Examples:
- A rendered Kubernetes manifest from Terraform.
- A rendered Auth service config.
- A cloud IAM policy export.
- A firewall rule export.

Format: JSON or YAML, with a content hash, a timestamp, and a
collector identity. Stored in the evidence store (see §3).

### 1.2 Activity evidence (AE)

Records of system activity that demonstrate the control is operating
in production.

Examples:
- An audit log record showing a privileged access review.
- A CI run log showing a security scan ran and passed.
- A pen-test report attached to the control.
- A training-completion record.

Format: pointer to the underlying record (ULID, URL), plus a digest
and collector identity.

### 1.3 Attestation evidence (AT)

A signed statement by a human (or designated role) attesting that the
control is operating as designed. Used sparingly; the platform
prefers CE and AE.

Examples:
- A quarterly self-attestation by the SecurityArchitect on a control.
- An annual external pen-test attestation.

Format: signed JSON-LD document with role, claim, scope, time, and
signature.

### 1.4 Inherited evidence (IN)

A reference to evidence produced by an external system (cloud
provider, upstream service) that the platform relies on.

Examples:
- The cloud provider's SOC 2 report.
- The cloud provider's ISO 27001 certificate.
- An upstream library's SBOM.

Format: pointer (URL + retrieval timestamp) and a digest of the
retrieved document.

## 2. Evidence sources

Every evidence record has a **source** — the system that produced or
collected it. Sources are versioned and authenticated; an unknown
source is rejected.

| Source | Type | Description | Authentication |
|---|---|---|---|
| `terraform` | CE | Exported from Terraform state | mTLS, signed manifest |
| `ci-pipeline` | AE, CE | GitHub Actions / equivalent runs | OIDC + signed provenance (SLSA) |
| `cd-pipeline` | AE, CE | ArgoCD / equivalent | OIDC + signed manifests |
| `audit-log` | AE | Reference to audit log record | Hash chain |
| `siem` | AE | Reference to SIEM event | Hash chain |
| `k8s-api` | CE | Live K8s API read | mTLS + RBAC |
| `cloud-iam` | CE | Cloud IAM policy export | Service identity |
| `k8s-audit` | AE | K8s audit log | Hash chain |
| `cloud-audit` | AE | Cloud audit log (CloudTrail, etc.) | Cloud-native integrity |
| `image-registry` | CE | Container image config | Cosign signature |
| `sbom` | CE, IN | CycloneDX SBOM | Provenance + signature |
| `pentest` | AT | External pen-test report | Signed delivery |
| `training-system` | AT | Training completion | SSO + signed record |
| `manual-attestation` | AT | Human attestation | WebAuthn signature |
| `compliance-service` | AE, CE | The Compliance service itself | Internal mTLS |

## 3. Evidence store

All evidence is stored in the **Compliance service** ("the evidence
store"). The store is:

- **Append-only** for CE and AE (you can supersede a CE with a newer
  one, but you cannot edit or delete; the old one is preserved with
  `superseded_by` linkage).
- **Append-only** for AT (signatures make this verifiable).
- **Versioned** — every record is content-addressed (hash-based ULID).
- **Indexed** by `(framework, control_id, evidence_type, tenant_id)`.
- **Tenant-scoped** — a tenant sees only its own evidence; the
  `auditor` and `compliance-officer` roles see cross-tenant.
- **Encrypted at rest** with the same envelope-encryption model as
  audit logs.
- **Signed** — every record is signed by the source; signatures are
  verifiable for the retention period.

### 3.1 Record lifecycle

```
Producer ──> collect ──> normalize ──> sign ──> store ──> index ──> expose
                   │                       │         │         │
                   │                       │         │         └─> API, UI, evidence bundles
                   │                       │         └─> notify POA&M (if violates baseline)
                   │                       └─> chain into daily Merkle root
                   └─> retry on failure
```

### 3.2 Collection cadence

Evidence is collected on a per-control basis. Cadence is one of:

- **On-change** — the source pushes evidence whenever the underlying
  state changes.
- **Hourly** — for high-volatility state.
- **Daily** — for most configuration and activity.
- **Weekly** — for slower-moving state.
- **Monthly** — for attestations and reviews.
- **Quarterly** — for periodic assessments.
- **Annual** — for external audits and pen-tests.

The cadence is recorded with each control in the framework mapping
and is enforced by the Compliance service: stale evidence raises a
`compliance.evidence.stale` event.

## 4. Evidence validation

Every evidence record is validated before being accepted into the
store. Validation includes:

1. **Schema validation** — the record conforms to the evidence-type
   schema.
2. **Source authentication** — the source is a known, registered
   collector and the signature verifies.
3. **Freshness** — the record is not older than the control's
   maximum-age setting.
4. **Baseline compliance** (for CE) — the configuration matches the
   expected baseline within tolerance. Drift raises a
   `compliance.evidence.drift` event.
5. **Completeness** — required fields are populated.
6. **Consistency** — the record does not contradict other recent
   evidence for the same control.

A record that fails validation is rejected; the source is notified;
the failure is itself audit-logged.

## 5. Continuous control monitoring (CCM)

The Compliance service runs **continuous control monitoring**:
scheduled jobs that evaluate evidence against expected state and
report status.

### 5.1 CCM pipeline

```
load control definitions
   │
   ▼
for each control:
   │
   ├─> load applicable evidence (by framework, control_id, tenant)
   │
   ├─> evaluate evidence against rule set
   │     (e.g., "all privileged actions in last 30 days have a review record")
   │
   ├─> compute status: implemented | drifted | partial | non-compliant | not-applicable
   │
   ├─> update POA&M if non-compliant
   │
   └─> publish status to dashboards
```

### 5.2 Rule types

CCM rules can be:

- **Threshold rules** — e.g., "patch age < 30 days for 95% of assets".
- **Presence rules** — e.g., "MFA enabled for 100% of human users".
- **Drift rules** — e.g., "current config matches baseline".
- **Process rules** — e.g., "quarterly review was performed on time".
- **Trend rules** — e.g., "no upward trend in failed logins".

Rules are written in a small DSL and version-controlled.

### 5.3 Output

The CCM pipeline produces:

- A **status record** per (control × tenant × framework).
- A **POA&M entry** when a non-compliance is detected.
- A **drift report** for any control in `drifted` status.
- **Dashboards** for SRE, Security, and Compliance teams.
- A **customer-facing compliance score** in the UI.

## 6. POA&M (Plan of Action & Milestones)

Every detected non-compliance becomes a POA&M item. POA&M items have:

- `id` — ULID.
- `control_id` — the framework control.
- `tenant_id` — the affected tenant (or platform).
- `severity` — critical / high / medium / low.
- `description` — what is non-compliant.
- `owner` — the teammate agent (for platform issues) or the customer
  point of contact.
- `due_date` — the SLA-derived due date.
- `status` — open / in-progress / awaiting-evidence / resolved /
  risk-accepted.
- `risk_acceptance` — signed by the ComplianceOfficer role if the
  decision is to accept the risk rather than remediate. Has its own
  expiry and requires re-acceptance.
- `evidence_links` — pointers to the resolution evidence once closed.

The POA&M is itself an evidence record and is signed by the
ComplianceOfficer role on creation and on closure.

## 7. Evidence bundles

The platform generates **evidence bundles** for auditors. A bundle is
a self-contained, signed JSON-LD document that contains:

- The control set in scope (e.g., "NIST 800-53 Moderate for tenant
  X from 2026-01-01 to 2026-03-31").
- The status of each control.
- The evidence records supporting each control (or pointers + digests
  if the records are too large).
- Any POA&M items that were open during the period.
- A signed attestation by the ComplianceOfficer role.

Bundles are produced on demand (auditor trigger) and on a schedule
(quarterly internal, annual external).

## 8. Customer-facing evidence

Customers access the evidence produced for them via the Compliance
service. The service exposes:

- A **compliance score** per framework.
- A **control status** UI: green / yellow / red per control.
- A **POA&M** view with the customer's own open items.
- A **drill-down** from a control to the evidence records supporting
  it.
- A **bundle export** (signed JSON-LD + PDF for human reviewers).
- An **API** for integrating with the customer's GRC tool.

All customer-facing access is itself audit-logged.

## 9. Personnel & training evidence

The platform tracks:

| Evidence | Source | Cadence |
|---|---|---|
| Background check completion | HR system | On hire + per re-screen |
| NDA / AUP signature | HR system | On hire + on change |
| Security training completion | Training system | Annual + on role change |
| Phishing sim results | Training system | Monthly |
| Role-based training (engineer, admin) | Training system | Annual |
| Incident response drill participation | IR service | Quarterly |
| Termination workflow execution | HR system | On event |
| Access review participation | Compliance service | Quarterly |

These feed the AT and PS control families in [`nist-800-53.md`](./nist-800-53.md).

## 10. Risk management evidence

The platform implements a risk register with:

- `id`, `title`, `description`
- `category` (strategic, operational, security, compliance, financial,
  reputational)
- `likelihood`, `impact`, `inherent_risk`
- `controls` — the controls that mitigate the risk
- `residual_risk`
- `treatment` — accept / mitigate / transfer / avoid
- `owner`, `review_date`
- `status`, `last_reviewed_at`

Risk reviews are scheduled quarterly and on material change. The
register is itself an evidence artefact and is referenced in the PM, RA
families of [`nist-800-53.md`](./nist-800-53.md).

## 11. Supply chain risk management (SCRM) evidence

For each vendor, the platform maintains:

- Vendor identity, jurisdiction, data classes processed.
- Tier (Critical / Important / Standard).
- Required controls per tier.
- Evidence collected:
  - SOC 2 Type II or ISO 27001 report (or equivalent).
  - SIG or CAIQ questionnaire.
  - Pen-test report (Critical/Important).
  - DPA + security exhibit.
  - Insurance certificate.
  - Sub-processor list.
- Risk score (algorithmic) and risk-acceptance decision.
- Review date and review notes.

Vendor reviews are scheduled annually and on incident. The vendor
register is itself an evidence artefact.

## 12. Privacy program evidence

The platform's privacy program produces:

- **Data inventory** — every data class, system, location, retention,
  legal basis.
- **Data flow diagrams** — per data class.
- **Privacy impact assessments (PIAs)** — per new data flow.
- **DPIA** (GDPR Art. 35) for high-risk processing.
- **Records of processing activities (RoPA)** — GDPR Art. 30 register.
- **Data subject request workflow** — intake, SLA tracking, evidence
  of completion.
- **Breach notification workflow** — 72 h regulator notification,
  customer notification.
- **Cookie / tracking register** — for the public marketing site.

These feed the PM-18 through PM-27 control families.

## 13. Insider threat program evidence

The platform implements an insider-threat program covering:

- Pre-employment screening.
- Continuous UEBA on production access.
- Privileged-access review campaigns.
- Termination workflow SLAs.
- Departing-employee data-access review.
- Anomaly escalation paths.

The program is documented in `evidence-collection.md` (this document
is the policy) and evidence is produced by the SIEM, Auth service, and
HR system.

## 14. Operations security (OpSec) program

The platform's OpSec program covers:

- Sensitive data classification and handling.
- Need-to-know access.
- Working-from-home controls (no local PII, no removable media).
- Clean-desk policy.
- Travel and meeting security.
- Social-media policy.

Evidence: training completion, periodic audits, exception register.

## 15. SLAs and timeliness

| Evidence class | Maximum age | Consequence if stale |
|---|---|---|
| CE (configuration) | 1 × collection cadence | `compliance.evidence.stale` alert; non-compliant status after 2× cadence |
| AE (activity) | 1 × collection cadence | Same |
| AT (attestation) | 1 × required frequency | Same |
| IN (inherited) | 1 year | Manual review triggered |
| Pen-test | 1 year | Non-compliant; POA&M auto-opened |
| Training | 1 year | Non-compliant; user access restrictions apply |

## 16. Audit of the audit (meta-controls)

The platform audits its own compliance program:

- The Compliance service itself is on the platform's monitoring stack.
- Changes to the rule DSL are reviewed by the ComplianceOfficer role
  and signed.
- The evidence store's hash chain is checked daily (§6.3 of
  [`audit-logging.md`](./audit-logging.md)).
- An annual internal audit reviews a random sample of controls for
  evidence quality.

## 17. Open questions (Sprint 1)

1. Will the platform offer a customer-managed key (CMK) option for
   evidence bundles? (Affects customer trust in bundle integrity.)
2. What is the target response time for auditors' requests for
   ad-hoc evidence bundles? (Affects customer SLA.)
3. Do we need a GRC tool integration (e.g., Drata, Vanta, Secureframe)
   in v1, or is the in-platform UI sufficient for the first 50
   customers?
4. Should evidence bundles be exportable in any standard format
   (e.g., OSCAL)? (Strongly recommended by US federal customers.)
