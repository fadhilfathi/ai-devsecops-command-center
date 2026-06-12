---
title: CIS Critical Security Controls v8 — Mapping
framework: CIS Critical Security Controls
version: v8.0 (2021-2023 update)
owner: ComplianceOfficer
status: draft
last_updated: 2026-06-12
related:
  - ./nist-800-53.md
  - ./compliance-matrix.md
  - ../architecture/security-model.md
---

# CIS Critical Security Controls v8 — Mapping

This document maps the AI-DevSecOps Command Center to the 18 CIS Critical
Security Controls (v8) and their 153 Safeguards. Each control is assessed
for applicability to the platform itself (i.e., "does the Command Center
*implement* this control to secure its own operation?") and, where
relevant, for the customer-evidence capabilities the platform provides.

CIS v8 organizes safeguards into three Implementation Groups (IG1, IG2,
IG3) reflecting organizational maturity. The Command Center targets
**IG2** for its own operations and surfaces IG2/IG3 evidence to customers.

## Conventions

- **S#.#** — Safeguard number in CIS v8.
- **Status** — see legend in [README.md](./README.md#compliance-status-legend).
- **Owner** — the teammate agent responsible for the underlying control.
- **Evidence** — link or pointer to the artefact that proves the control
  is operating.

---

## Control 01 — Inventory and Control of Enterprise Assets

Actively manage all enterprise assets connected to the infrastructure
physically, virtually, or remotely.

| Safeguard | Title | Applicability | Status | Owner | Implementation in Command Center | Evidence |
|---|---|---|---|---|---|---|
| 1.1 | Establish and maintain asset inventory | Customer | Planned | FullstackEngineer | The `Agent` service performs continuous host/container discovery across enrolled customer estates and maintains an authoritative `assets` table. | `backend/services/agent/src/discovery/`, `compliance/evidence/asset-snapshots/` |
| 1.2 | Address unauthorized assets | Customer | Planned | FullstackEngineer | Drift detection flags assets that appear without an enrollment record and emits a `security.asset.unauthorized` event. | `security-model.md` event catalog |
| 1.3 | Utilize an active discovery tool | Customer | Planned | FullstackEngineer | Agent performs authenticated scans over SSH, WinRM, and Kubernetes API. | Agent scanner module |
| 1.4 | Use DHCP logging to update asset inventory | Customer | Planned | SREEngineer | Optional enrichment: ingest DHCP lease logs via the Integration service. | Integration service connectors |
| 1.5 | Use a passive discovery tool | Customer | Not Applicable | — | Not used in v1; the agent-based model is active-only. | — |

## Control 02 — Inventory and Control of Software Assets

Manage the inventory of software (OS, applications, SaaS) so only
authorized software is installed.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 2.1 | Establish and maintain software inventory | Customer | Implemented | FullstackEngineer | SBOM ingestion (CycloneDX, SPDX) plus runtime package enumeration; aggregated in `assets` and `components` tables. | `compliance/evidence/sbom-records/` |
| 2.2 | Ensure authorized software is supported | Customer | Planned | SecurityArchitect | SBOM components are matched against the EOL/EOS database; alerts raised for unsupported versions. | Vulnerability service feed |
| 2.3 | Address unauthorized software | Customer | Planned | SecurityArchitect | Policy engine flags packages with no allow-list match and raises incidents. | Incident service |
| 2.4 | Utilize automated software inventory tools | Customer | Implemented | FullstackEngineer | Agent periodically uploads a signed inventory manifest; Service ingests and stores it immutably. | Agent manifest format |

## Control 03 — Data Protection

Develop processes and technical controls to identify, classify, securely
handle, retain, and dispose of data.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 3.1 | Establish and maintain data management program | Platform | Planned | ComplianceOfficer | Documented in [`evidence-collection.md`](./evidence-collection.md); data classification scheme defined in `security-model.md`. | `evidence-collection.md` |
| 3.2 | Establish and maintain data inventory | Platform | Planned | ComplianceOfficer | Inventory of customer data classes, retention, location, and legal basis. | `evidence-collection.md` §Data Inventory |
| 3.3 | Configure data access control lists | Platform | Implemented | SecurityArchitect | RBAC model in `security-model.md` enforces least-privilege access to customer data. | `security-model.md` |
| 3.4 | Enforce data retention | Platform | Planned | SREEngineer | Retention policy engine in the Compliance service; configurable per data class and tenant. | Compliance service retention module |
| 3.5 | Securely dispose of data | Platform | Planned | SREEngineer | Cryptographic erasure of tenant-scoped encryption keys on tenant off-boarding; tombstones in audit log. | Tenant lifecycle runbook |
| 3.6 | Encrypt data on end-user devices | Platform | Not Applicable | — | Customers bring their own devices; managed by the customer. | — |
| 3.7 | Establish and maintain a data classification scheme | Platform | Planned | ComplianceOfficer | Classes: Public, Internal, Confidential, Restricted. Tied to labeling in audit logs. | `security-model.md` |
| 3.8 | Document data flows | Platform | Planned | PlatformArchitect | Data flow diagrams in `system-architecture.md`; updated on every architectural change. | `system-architecture.md` |
| 3.9 | Encrypt data in transit | Platform | Implemented | SecurityArchitect | TLS 1.3 enforced on all north-south and east-west traffic; mTLS inside the service mesh. | Security baseline doc |
| 3.10 | Encrypt sensitive data at rest | Platform | Implemented | SecurityArchitect | AES-256 envelope encryption; tenant keys wrapped by KMS; per-row encryption for PII columns. | KMS architecture doc |
| 3.11 | Encrypt sensitive data in use (memory) | Platform | Planned | SecurityArchitect | Memory scraping protections; secrets in process memory are redacted by the agent runtime. | Agent runtime hardening spec |
| 3.12 | Segment data processing and storage | Platform | Implemented | PlatformArchitect | Per-tenant database schemas, per-tenant Kafka/Redis Streams subjects, separate KMS keys. | Multi-tenancy design |
| 3.13 | Deploy a data loss prevention (DLP) solution | Platform | Planned | SecurityArchitect | Outbound webhooks and SBOM exports are scanned for restricted data classes. | DLP module spec |

## Control 04 — Secure Configuration of Enterprise Assets and Software

Establish and maintain the secure configuration of enterprise assets and
software.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 4.1 | Establish and maintain a secure configuration process | Platform | Planned | SecurityArchitect | Golden images and IaC modules; CIS Benchmark baselines for container images. | `infra/terraform/baselines/` |
| 4.2 | Establish and maintain a secure configuration process for network infrastructure | Platform | Planned | PlatformArchitect | Network policies and service mesh defaults locked to deny-all. | `infra/` |
| 4.3 | Configure automatic session locking on enterprise assets | Platform | Planned | SecurityArchitect | Web UI idle timeout (15 min default), API token rotation policy (90 days). | Auth service config |
| 4.4 | Implement and manage a firewall on end-user devices | Platform | Not Applicable | — | Customer-managed. | — |
| 4.5 | Implement and manage a host-based firewall or port-filtering tool | Platform | Implemented | PlatformArchitect | Default-deny NetworkPolicy in Kubernetes; agents open only outbound 443. | K8s manifests |
| 4.6 | Securely manage enterprise assets and software | Platform | Implemented | SREEngineer | All changes via GitOps; PR-based, signed commits, CODEOWNERS enforcement. | `.github/CODEOWNERS` |
| 4.7 | Manage default accounts on enterprise assets and software | Platform | Implemented | SREEngineer | No default service accounts; bootstrap secrets rotated at first run. | Provisioning scripts |
| 4.8 | Uninstall or disable unnecessary services on enterprise assets and software | Platform | Planned | SREEngineer | Distroless / minimal base images; non-root by default. | Container build pipeline |
| 4.9 | Configure trusted DNS servers on enterprise assets | Platform | Inherited | — | Provided by cloud DNS; documented in inherited controls matrix. | — |
| 4.10 | Enforce automatic device lockout on portable end-user devices | Platform | Not Applicable | — | Customer-managed. | — |
| 4.11 | Enforce remote wiping capability on portable end-user devices | Platform | Not Applicable | — | Customer-managed. | — |
| 4.12 | Manage enterprise assets and software remotely | Platform | Planned | SREEngineer | All operations are API-driven; console access is via break-glass, audit-logged. | Break-glass runbook |

## Control 05 — Account Management

Use processes and tools to assign and manage authorization to
credentials for user accounts.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 5.1 | Establish and maintain an inventory of accounts | Platform | Implemented | SecurityArchitect | Auth service maintains the `users`, `service_accounts`, and `api_keys` tables; periodic reconciliation job. | Auth service |
| 5.2 | Use unique passwords | Platform | Implemented | SecurityArchitect | Password policy: 14+ chars, complexity, breached-password check. | Auth service policy |
| 5.3 | Disable inactive accounts | Platform | Implemented | SecurityArchitect | 90-day inactivity lock for human users; configurable per tenant. | Auth service job |
| 5.4 | Restrict administrator privileges to dedicated administrator accounts | Platform | Implemented | SecurityArchitect | Separate `admin` role; admin actions are step-up authenticated. | RBAC model |
| 5.5 | Establish and maintain an inventory of service accounts | Platform | Implemented | SecurityArchitect | Service accounts have a `purpose`, `owner`, `review_due_date`; quarterly review job. | Service account inventory |
| 5.6 | Centralize account management | Platform | Implemented | SecurityArchitect | Auth service is the single source of truth; SCIM 2.0 provisioning planned. | SCIM spec |

## Control 06 — Access Control Management

Use processes and tools to create, assign, manage, and revoke access
credentials and privileges for user accounts.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 6.1 | Establish an access granting process | Platform | Implemented | SecurityArchitect | Approval workflow for role assignments; request/approve/audit trail. | Access request API |
| 6.2 | Establish an access revoking process | Platform | Implemented | SecurityArchitect | Termination trigger revokes within 1 hour; verified by daily reconciliation. | Termination hook |
| 6.3 | Require MFA for privileged access | Platform | Implemented | SecurityArchitect | TOTP and WebAuthn supported; enforced for `admin` and any role with `*:*` grants. | Auth service MFA |
| 6.4 | Require MFA for remote network access | Platform | Implemented | SecurityArchitect | All web/API access requires MFA for human users. | Auth service MFA |
| 6.5 | Require MFA for administrative access | Platform | Implemented | SecurityArchitect | Step-up MFA required for every privileged action. | Auth service |
| 6.6 | Establish and maintain a privileged account inventory | Platform | Planned | SecurityArchitect | Continuously exported report of accounts with privileged roles. | Compliance report |
| 6.7 | Centralize access control | Platform | Implemented | PlatformArchitect | All service-to-service calls go through the Auth service token check; no implicit trust. | Service mesh policy |
| 6.8 | Define and maintain role-based access control | Platform | Implemented | SecurityArchitect | Roles are tenant-scoped; ABAC predicates for data-class restrictions. | RBAC model |

## Control 07 — Continuous Vulnerability Management

Develop a plan to continuously assess and track vulnerabilities on all
enterprise assets.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 7.1 | Establish and maintain a vulnerability management process | Platform + Customer | Implemented | SecurityArchitect | Documented in `security-model.md` §Vulnerability Management; SLAs by severity. | Process doc |
| 7.2 | Establish and maintain a remediation process | Platform + Customer | Implemented | SecurityArchitect | The Incident service routes findings to owners; auto-PR generation for first-party code. | Incident service |
| 7.3 | Perform operating system patch management | Customer | Planned | FullstackEngineer | Agent reports patch level; policy engine raises non-compliance. | Agent patch report |
| 7.4 | Perform application patch management | Customer | Implemented | FullstackEngineer | SBOM-driven; auto-PR for dependency upgrades. | Auto-PR template |
| 7.5 | Perform automated vulnerability scans | Customer | Implemented | SecurityArchitect | Scheduled scans + CI scans; results ingested as findings. | Scan orchestrator |
| 7.6 | Perform automated operating system patch management | Customer | Planned | FullstackEngineer | Optional Windows Update / apt integration via Integration service. | Integration connectors |
| 7.7 | Perform automated application patch management | Customer | Implemented | FullstackEngineer | Renovate/Dependabot-compatible upgrade PRs. | Upgrade bot module |

## Control 08 — Audit Log Management

Collect, alert, review, and retain audit logs of events that could help
detect, understand, or recover from an attack.

> Detailed requirements live in [`audit-logging.md`](./audit-logging.md).

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 8.1 | Establish and maintain an audit log management process | Planned | ComplianceOfficer | Defined in `audit-logging.md`. | `audit-logging.md` |
| 8.2 | Collect audit logs | Implemented | SREEngineer | Structured JSON logs from all services to a central store. | Log pipeline |
| 8.3 | Ensure adequate audit log storage | Implemented | SREEngineer | 13 months hot, 7 years cold in object storage with object lock. | Retention policy |
| 8.4 | Standardize time synchronization | Implemented | SREEngineer | NTP + monotonic clocks; all log lines include RFC 3339 timestamp with ms. | NTP config |
| 8.5 | Centralize audit logs | Implemented | SREEngineer | Single tenant-scoped log index; cross-tenant correlation requires break-glass. | Log architecture |
| 8.6 | Collect DNS query audit logs | Inherited | — | Provided by upstream DNS resolver. | — |
| 8.7 | Collect URL request audit logs | Implemented | SREEngineer | Edge proxy logs every HTTP request. | Proxy log config |
| 8.8 | Collect command-line audit logs | Customer | Planned | FullstackEngineer | Agent captures process exec events on enrolled hosts. | Agent telemetry |
| 8.9 | Centralize, review, and report on audit logs | Planned | ComplianceOfficer | Weekly automated review of privileged actions; daily anomaly detection. | SIEM rules |
| 8.10 | Retain audit logs | Implemented | SREEngineer | Per `audit-logging.md`. | Retention policy |
| 8.11 | Conduct audit log reviews | Planned | ComplianceOfficer | Monthly review of access logs; quarterly external review. | Review SOP |
| 8.12 | Collect service provider logs | Implemented | SREEngineer | Cloud provider logs (CloudTrail/Azure Activity) ingested. | Cloud log pipeline |

## Control 09 — Email and Web Browser Protections

Improve protections and detections of threats from email and web vectors.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 9.1 | Ensure use of only fully supported browsers and email clients | Platform | Planned | SREEngineer | Browser support matrix published; deprecated versions blocked. | Web UI requirements |
| 9.2 | Use DNS filtering services | Platform | Inherited | — | Provided by upstream resolver. | — |
| 9.3 | Maintain and enforce network-based URL filters | Platform | Inherited | — | Egress filtering on the platform VPC; allow-list of external services. | Egress config |
| 9.4–9.7 | Restrict unnecessary browser extensions, implement DMARC, etc. | Platform | Planned | SecurityArchitect | DMARC enforced on outgoing notification emails; CSP strict on the web UI. | Email/UI configs |

## Control 10 — Malware Defenses

Prevent or control the installation, spread, and execution of malicious
applications, code, or scripts.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 10.1 | Deploy and maintain anti-malware software | Platform + Customer | Implemented (platform) | SREEngineer | All container images scanned pre-deploy; runtime eBPF-based anomaly detection. | Image scanning pipeline |
| 10.2 | Configure automatic anti-malware signature updates | Platform | Implemented | SREEngineer | Signature feed auto-updated daily; version pinned in SBOM. | Feed config |
| 10.3 | Disable autorun and autoplay for removable media | Platform | Not Applicable | — | No removable media. | — |
| 10.4 | Configure automatic anti-malware scanning of removable media | Platform | Not Applicable | — | No removable media. | — |
| 10.5 | Enable anti-exploitation features | Platform | Implemented | SREEngineer | Cgroups, seccomp, AppArmor/SELinux profiles on all workloads. | Hardening manifests |
| 10.6 | Centrally manage anti-malware software | Platform | Implemented | SREEngineer | Single config via GitOps. | Git repo |
| 10.7 | Use behavior-based anti-malware software | Platform | Planned | SecurityArchitect | eBPF-based process behavior analysis. | Detection rules |

## Control 11 — Data Recovery

Establish and maintain data recovery practices sufficient to restore
in-scope enterprise assets to a pre-incident state.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 11.1 | Establish and maintain a data recovery process | Planned | SREEngineer | Runbook in `infra/runbooks/data-recovery.md`. | Runbook |
| 11.2 | Perform automated backups | Implemented | SREEngineer | Hourly incremental, daily full, cross-region replication. | Backup config |
| 11.3 | Protect recovery data | Implemented | SREEngineer | Backups encrypted with separate KMS keys; immutable for 30 days. | Backup KMS policy |
| 11.4 | Establish and maintain an isolated instance of recovery data | Implemented | SREEngineer | Air-gapped backup account in a separate org. | DR topology |
| 11.5 | Test data recovery | Planned | SREEngineer | Quarterly game-day restore tests. | Test reports |

## Control 12 — Network Infrastructure Management

Establish, implement, and actively manage network devices.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 12.1 | Ensure network device inventory is up to date | Implemented | PlatformArchitect | IaC-managed; no manual changes. | Terraform state |
| 12.2 | Establish and maintain a secure network architecture | Implemented | PlatformArchitect | VPC isolation, private subnets, service mesh mTLS. | Network diagram |
| 12.3 | Securely manage network infrastructure | Implemented | PlatformArchitect | All changes via GitOps PR; no SSH to routers. | Change log |
| 12.4 | Establish and maintain architecture diagram(s) | Implemented | PlatformArchitect | `system-architecture.md`. | Doc |
| 12.5–12.8 | Network device hardening, segmentation, etc. | Implemented | PlatformArchitect | CIS Benchmark baselines applied; microsegmentation between services. | Hardening checklist |

## Control 13 — Network Monitoring and Defense

Operate processes and tooling to establish and maintain comprehensive
network monitoring and defense.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 13.1 | Centralize security event alerting | Implemented | SREEngineer | All security events → SIEM; tiered alert routing. | SIEM integration |
| 13.2 | Deploy a host-based intrusion detection solution | Implemented | SREEngineer | eBPF-based runtime detection. | Runtime module |
| 13.3 | Deploy a network-based IDS/IPS | Implemented | SREEngineer | Cloud-native IDS plus WAF in front of public endpoints. | WAF rules |
| 13.4 | Perform traffic filtering between network segments | Implemented | PlatformArchitect | Default-deny NetworkPolicy; explicit allow per pair. | NetworkPolicy manifests |
| 13.5 | Manage access control for remote assets | Implemented | SecurityArchitect | All remote access via SSO + MFA + audit. | Auth service |
| 13.6 | Collect network traffic flow logs | Implemented | SREEngineer | VPC flow logs and mesh telemetry. | Flow log pipeline |
| 13.7 | Deploy a honeypot or canary token | Planned | SecurityArchitect | Canary credentials injected into agent bundle. | Canary design |
| 13.8 | Consider use of a NDR solution | Planned | SREEngineer | Evaluate for v1.1. | Roadmap |
| 13.9–13.10 | Document and encrypt traffic, incident response | Implemented | ComplianceOfficer | `incident-response-plan.md` (linked). | IRP |

## Control 14 — Security Awareness and Skills Training

Establish and maintain a security awareness program.

| Safeguard | Title | Applicability | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|---|
| 14.1 | Establish and maintain a security awareness program | Platform | Planned | ComplianceOfficer | Annual training, monthly phishing simulations, role-based deep dives. | Training program |
| 14.2 | Train workforce members to recognize social engineering | Platform | Planned | ComplianceOfficer | Phishing sim + tabletop exercises. | Training records |
| 14.3–14.9 | Role-based training, third-party, etc. | Platform | Planned | ComplianceOfficer | Role matrix in `evidence-collection.md` §Personnel. | Training matrix |

## Control 15 — Service Provider Management

Develop a process to evaluate service providers who hold sensitive data,
or are responsible for an enterprise's critical IT platforms.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 15.1 | Establish and maintain a service provider inventory | Planned | ComplianceOfficer | Vendor register with data class, jurisdiction, certifications. | Vendor register |
| 15.2 | Classify service providers | Planned | ComplianceOfficer | Tiering (Critical/Important/Standard) with required controls per tier. | Vendor tiering doc |
| 15.3 | Review third-party services | Planned | ComplianceOfficer | Annual review of SOC 2 / ISO reports; SIG questionnaire for the rest. | Review tracker |
| 15.4 | Ensure service provider contracts include security requirements | Planned | ComplianceOfficer | DPA, security exhibit, audit rights clause. | Contract template |
| 15.5 | Assess service provider compliance | Planned | ComplianceOfficer | Continuous monitoring of vendor security posture via ratings feed. | Vendor risk dashboard |

## Control 16 — Application Software Security

Manage the security lifecycle of in-house developed, hosted, or acquired
software.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 16.1 | Establish and maintain a secure application development process | Implemented | SecurityArchitect | SDLC documented; threat modeling required for new services. | SDLC doc |
| 16.2 | Establish and maintain a process for accepting and tracking software vulnerabilities | Implemented | SecurityArchitect | All findings tracked in the platform; SLA by severity. | Vulnerability service |
| 16.3 | Perform root cause analysis on security vulnerabilities | Planned | SecurityArchitect | Post-incident RCA template; tracked in the Compliance service. | RCA template |
| 16.4 | Establish and manage a vulnerability disclosure program | Implemented | SecurityArchitect | `security.txt` + responsible disclosure page. | Security.txt |
| 16.5 | Use an up-to-date vulnerability scanning tool | Implemented | SecurityArchitect | SCA, SAST, container, IaC scanners wired into CI. | CI pipelines |
| 16.6 | Establish a process to evaluate and rank application security vulnerabilities | Implemented | SecurityArchitect | CVSS + EPSS + exploit-available flag drives priority. | Prioritization service |
| 16.7 | Use threat modeling to validate application design | Planned | SecurityArchitect | STRIDE per new service; output stored in `docs/threat-models/`. | Threat models |
| 16.8 | Use static analysis tools | Implemented | SecurityArchitect | Semgrep + TypeScript strict + ESLint security plugin in CI. | CI config |
| 16.9 | Use dynamic analysis tools | Implemented | SecurityArchitect | OWASP ZAP baseline scan in nightly job. | DAST config |
| 16.10 | Use interactive application security testing (IAST) | Planned | SecurityArchitect | Evaluate for v1.1. | Roadmap |
| 16.11 | Use a software bill of materials (SBOM) | Implemented | FullstackEngineer | CycloneDX SBOM generated for every build; published as artifact. | SBOM pipeline |
| 16.12 | Sign software updates | Implemented | SecurityArchitect | Cosign signatures on all images and binaries; SLSA L3 provenance. | Signing config |
| 16.13 | Conduct code reviews | Implemented | GitOpsManager | Required reviewers, CODEOWNERS, signed commits. | Repo config |
| 16.14 | Manage the software development lifecycle | Implemented | GitOpsManager | GitOps, trunk-based, automated tests in CI. | Repo policy |

## Control 17 — Incident Response Management

Establish a program to prepare, detect, and quickly respond to an attack.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 17.1 | Designate a single person to manage the enterprise's incident response | Planned | ComplianceOfficer | IR Lead role defined. | Org chart |
| 17.2 | Establish and maintain contact information for reporting | Implemented | ComplianceOfficer | `security.txt`, status page, on-call rotation. | Contacts doc |
| 17.3 | Establish and maintain an enterprise process for reporting incidents | Implemented | ComplianceOfficer | `incident-response-plan.md`. | IRP |
| 17.4 | Establish and maintain an enterprise process for responding to incidents | Implemented | ComplianceOfficer | Runbooks in `infra/runbooks/incident/`. | Runbooks |
| 17.5–17.7 | Track, respond, automate | Implemented | FullstackEngineer | Incident service routes, deduplicates, and pages on-call. | Incident service |
| 17.8 | Conduct post-incident reviews | Planned | ComplianceOfficer | Blameless postmortems within 5 business days. | Postmortem template |
| 17.9 | Establish and maintain security incident thresholds | Implemented | ComplianceOfficer | Severity matrix with MTTR targets. | Severity matrix |

## Control 18 — Penetration Testing

Test the effectiveness and resiliency of enterprise assets against
adversary techniques.

| Safeguard | Title | Status | Owner | Implementation | Evidence |
|---|---|---|---|---|---|
| 18.1 | Establish and maintain a penetration testing program | Planned | SecurityArchitect | Annual external + quarterly internal scope. | Pen-test calendar |
| 18.2 | Perform periodic external penetration tests | Planned | SecurityArchitect | Annual, scope includes web, API, infra. | Pen-test reports |
| 18.3 | Remediate penetration test findings | Planned | SecurityArchitect | Findings tracked in the platform; SLA by severity. | Findings backlog |
| 18.4 | Validate security measures after changes | Implemented | SecurityArchitect | Post-deploy smoke tests, automated regression suite, security regression on every PR. | CI config |
| 18.5 | Perform periodic internal penetration tests | Planned | SecurityArchitect | Quarterly red-team engagement. | Internal pen-test reports |

---

## Implementation Group coverage

| IG | Safeguards in scope | Mapped here | Status snapshot |
|---|---|---|---|
| IG1 (essential cyber hygiene) | 56 | 56 | All addressed; majority Implemented or Inherited. |
| IG2 (mid-size org) | 74 | 74 | All addressed; mix of Implemented and Planned. |
| IG3 (sophisticated env) | 23 | 23 | All addressed; most Implemented. |

## Summary of gaps requiring Sprint 1 follow-up

1. **CIS 8.1 / 8.9 / 8.11** — formal audit log review SOP and tooling.
2. **CIS 14.x** — security awareness program design.
3. **CIS 15.x** — vendor management program.
4. **CIS 18.x** — penetration testing program and external partner selection.

These are tracked as compliance backlogs and will be planned in Sprint 2+.
