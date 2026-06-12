---
title: Compliance Cross-Framework Matrix
owner: ComplianceOfficer
status: draft
version: 0.1.0
last_updated: 2026-06-12
related:
  - ./nist-800-53.md
  - ./cis-controls-v8.md
  - ./audit-logging.md
  - ./evidence-collection.md
---

# Compliance Cross-Framework Matrix

This document maps controls across the frameworks the AI-DevSecOps
Command Center supports, so a control owner can see at a glance which
frameworks are affected by a change. It also supports
**cross-walking** a customer audit request that uses one framework's
vocabulary to the platform's own evidence.

The primary frameworks covered are:

- **CIS Critical Security Controls v8** (153 safeguards across 18
  controls) — see [`cis-controls-v8.md`](./cis-controls-v8.md)
- **NIST SP 800-53 Rev. 5** (Moderate baseline, ~325 controls) — see
  [`nist-800-53.md`](./nist-800-53.md)

The matrix below maps the **CIS v8** safeguards to the relevant
**NIST 800-53** controls. The reverse mapping (NIST → CIS) can be
derived but is not duplicated here.

> Cross-walk sources: CIS's own published crosswalk, NIST's
> Cybersecurity Framework (CSF) mappings, and the platform's
> implementation.

## 1. CIS v8 → NIST 800-53

| CIS Safeguard | Title (abbrev.) | NIST 800-53 controls |
|---|---|---|
| **Control 01 — Inventory of Enterprise Assets** | | |
| 1.1 | Establish and maintain asset inventory | CM-8, PM-5 |
| 1.2 | Address unauthorized assets | CM-8, SI-4 |
| 1.3 | Active discovery tool | CM-8, RA-5 |
| 1.4 | DHCP logging | AU-2, AU-3 |
| 1.5 | Passive discovery | CM-8, SI-4 |
| **Control 02 — Inventory of Software Assets** | | |
| 2.1 | Software inventory | CM-8, SA-10 |
| 2.2 | Authorized software is supported | SA-22, SI-2 |
| 2.3 | Address unauthorized software | CM-7, SI-4 |
| 2.4 | Automated software inventory | CM-8, SI-7 |
| **Control 03 — Data Protection** | | |
| 3.1 | Data management program | PM-18, PM-19, PM-23, PM-24 |
| 3.2 | Data inventory | PM-24, PM-25 |
| 3.3 | Data access control lists | AC-3, AC-6 |
| 3.4 | Enforce data retention | SI-12, AU-11 |
| 3.5 | Securely dispose of data | MP-6, SI-12(3) |
| 3.6 | Encrypt data on end-user devices | (out of scope for SaaS) |
| 3.7 | Data classification scheme | RA-2, AC-16, PM-26 |
| 3.8 | Document data flows | PL-8, SA-4(12), PM-24 |
| 3.9 | Encrypt data in transit | SC-8, SC-13 |
| 3.10 | Encrypt sensitive data at rest | SC-28, SC-13 |
| 3.11 | Encrypt sensitive data in use | SC-28(3), SI-16 |
| 3.12 | Segment data processing and storage | SC-32, AC-4 |
| 3.13 | DLP | AC-23, SI-15 |
| **Control 04 — Secure Configuration** | | |
| 4.1 | Secure configuration process | CM-2, CM-9 |
| 4.2 | Secure network config | CM-2, CM-6 |
| 4.3 | Automatic session locking | AC-2(5), AC-12 |
| 4.4 | Firewall on end-user devices | (out of scope) |
| 4.5 | Host-based firewall | CM-7, SC-7 |
| 4.6 | Securely manage enterprise assets | CM-3, CM-5 |
| 4.7 | Manage default accounts | AC-2, IA-5 |
| 4.8 | Uninstall unnecessary services | CM-7, SA-7 |
| 4.9 | Trusted DNS | SC-20, SC-21 |
| 4.10 | Automatic device lockout | (out of scope) |
| 4.11 | Remote wiping | (out of scope) |
| 4.12 | Manage assets remotely | AC-17, MA-2 |
| **Control 05 — Account Management** | | |
| 5.1 | Account inventory | AC-2, IA-4 |
| 5.2 | Unique passwords | IA-5(1) |
| 5.3 | Disable inactive accounts | AC-2(3) |
| 5.4 | Restrict administrator privileges | AC-2(7), AC-6(5) |
| 5.5 | Service account inventory | AC-2, IA-4 |
| 5.6 | Centralize account management | AC-2, IA-4(5) |
| **Control 06 — Access Control Management** | | |
| 6.1 | Access granting process | AC-2, AC-6 |
| 6.2 | Access revoking process | AC-2(2), PS-4 |
| 6.3 | Require MFA for privileged access | IA-2(1), IA-2(2) |
| 6.4 | Require MFA for remote access | IA-2(2), AC-17 |
| 6.5 | Require MFA for admin access | IA-2(1) |
| 6.6 | Privileged account inventory | AC-2, AC-6(6) |
| 6.7 | Centralize access control | AC-3, AC-6 |
| 6.8 | RBAC | AC-2, AC-3, AC-5, AC-6 |
| **Control 07 — Continuous Vulnerability Management** | | |
| 7.1 | Vulnerability management process | RA-5, SI-2 |
| 7.2 | Remediation process | RA-5, SI-2 |
| 7.3 | OS patch management | SI-2, MA-2 |
| 7.4 | App patch management | SI-2, SA-10 |
| 7.5 | Automated vulnerability scans | RA-5 |
| 7.6 | Automated OS patch management | SI-2, MA-2 |
| 7.7 | Automated app patch management | SI-2, SA-10 |
| **Control 08 — Audit Log Management** | | |
| 8.1 | Audit log management process | AU-1, AU-2 |
| 8.2 | Collect audit logs | AU-2, AU-3 |
| 8.3 | Adequate audit log storage | AU-4, AU-11 |
| 8.4 | Standardize time synchronization | AU-8 |
| 8.5 | Centralize audit logs | AU-3(2), AU-6(4) |
| 8.6 | Collect DNS query logs | AU-2 |
| 8.7 | Collect URL request logs | AU-2, AU-3 |
| 8.8 | Collect command-line audit logs | AU-2 |
| 8.9 | Centralize, review, report audit logs | AU-6, AU-7 |
| 8.10 | Retain audit logs | AU-11 |
| 8.11 | Conduct audit log reviews | AU-6 |
| 8.12 | Collect service provider logs | AU-2, AU-12 |
| **Control 09 — Email and Web Browser Protections** | | |
| 9.1 | Fully supported browsers | SA-22 |
| 9.2 | DNS filtering | SC-20, SC-21 |
| 9.3 | URL filters | SC-7, SI-4 |
| 9.4–9.7 | Browser extensions, DMARC, etc. | SC-7, SI-8 |
| **Control 10 — Malware Defenses** | | |
| 10.1 | Deploy anti-malware | SI-3 |
| 10.2 | Automatic signature updates | SI-3, SI-8 |
| 10.3 | Disable autorun | (out of scope) |
| 10.4 | Auto-scan removable media | (out of scope) |
| 10.5 | Anti-exploitation features | SI-16, SC-39 |
| 10.6 | Central management | SI-3(1) |
| 10.7 | Behavior-based | SI-4, SI-3 |
| **Control 11 — Data Recovery** | | |
| 11.1 | Data recovery process | CP-1, CP-2 |
| 11.2 | Automated backups | CP-9 |
| 11.3 | Protect recovery data | CP-9(3), SC-28 |
| 11.4 | Isolated instance of recovery data | CP-9(3) |
| 11.5 | Test data recovery | CP-4, CP-9(1) |
| **Control 12 — Network Infrastructure Management** | | |
| 12.1 | Network device inventory | CM-8 |
| 12.2 | Secure network architecture | PL-8, SC-7 |
| 12.3 | Securely manage network | CM-3, CM-5 |
| 12.4 | Architecture diagrams | PL-8 |
| 12.5–12.8 | Hardening, segmentation | CM-6, SC-7 |
| **Control 13 — Network Monitoring and Defense** | | |
| 13.1 | Centralize security alerts | AU-6, SI-4 |
| 13.2 | Host-based IDS | SI-4, SI-4(1) |
| 13.3 | Network IDS/IPS | SI-4(1) |
| 13.4 | Traffic filtering between segments | SC-7, AC-4 |
| 13.5 | Manage remote access | AC-17 |
| 13.6 | Network flow logs | AU-2, SI-4 |
| 13.7 | Honeypot / canary | SC-26, SC-30 |
| 13.8 | NDR | SI-4 |
| 13.9 | Document traffic | PL-8 |
| 13.10 | Encrypt traffic | SC-8 |
| **Control 14 — Security Awareness and Skills Training** | | |
| 14.1 | Security awareness program | AT-1, AT-2 |
| 14.2 | Social engineering training | AT-2(1), AT-2(2) |
| 14.3 | Role-based training | AT-3 |
| 14.4 | Suspicious communications | AT-2 |
| 14.5 | Sensitive data recognition | AT-3 |
| 14.6 | Insider threat | AT-2(2), PM-12 |
| 14.7 | Social media | PL-4(1) |
| 14.8 | Third-party security | SA-16, SR-6 |
| 14.9 | Maximum functional development | SA-16 |
| **Control 15 — Service Provider Management** | | |
| 15.1 | Service provider inventory | SR-1, PM-30 |
| 15.2 | Classify service providers | SR-3 |
| 15.3 | Review third-party services | SR-6, SA-9 |
| 15.4 | Contracts with security requirements | SA-9, SR-8 |
| 15.5 | Assess service provider compliance | SR-6, CA-7 |
| 15.6 | Monitor service providers | SR-6, CA-7 |
| 15.7 | Capacity and redundancy | CP-2, CP-7 |
| **Control 16 — Application Software Security** | | |
| 16.1 | Secure app development process | SA-3, SA-15 |
| 16.2 | Accept and track vulnerabilities | RA-5, SI-2 |
| 16.3 | Root cause analysis | IR-4, SI-2 |
| 16.4 | Vulnerability disclosure | RA-5(11) |
| 16.5 | Up-to-date scanning tools | RA-5, SI-7 |
| 16.6 | Evaluate and rank | RA-3, SI-2 |
| 16.7 | Threat modeling | SA-15, RA-5 |
| 16.8 | Static analysis | SA-11(1) |
| 16.9 | Dynamic analysis | SA-11(2) |
| 16.10 | IAST | SA-11(9) |
| 16.11 | SBOM | SA-10, SR-11 |
| 16.12 | Sign software updates | SI-7, SR-4 |
| 16.13 | Code reviews | SA-11(3), SA-15 |
| 16.14 | Manage SDLC | SA-3, SA-15 |
| **Control 17 — Incident Response Management** | | |
| 17.1 | Designate IR lead | IR-1, PM-2 |
| 17.2 | Contact information | IR-1, IR-8 |
| 17.3 | Reporting process | IR-6, IR-8 |
| 17.4 | Response process | IR-4 |
| 17.5 | Track incidents | IR-4, IR-6 |
| 17.6 | Containment | IR-4 |
| 17.7 | Automate response | IR-4(1), IR-4(2) |
| 17.8 | Post-incident reviews | IR-4, IR-5 |
| 17.9 | Incident thresholds | IR-4, IR-6 |
| **Control 18 — Penetration Testing** | | |
| 18.1 | Pen-test program | CA-8, RA-5(9) |
| 18.2 | External pen-test | CA-8, CA-8(1) |
| 18.3 | Remediate findings | CA-5, SI-2 |
| 18.4 | Validate after changes | CA-7, SI-7 |
| 18.5 | Internal pen-test | CA-8(2), RA-5 |

## 2. Control family quick reference

| Topic | CIS Control | NIST Family | Primary owner (this team) |
|---|---|---|---|
| Asset & software inventory | 1, 2 | CM, PM | FullstackEngineer |
| Data protection & classification | 3 | SC, SI, PM | ComplianceOfficer + SecurityArchitect |
| Secure configuration | 4, 12 | CM, SC | SREEngineer + PlatformArchitect |
| Account & access management | 5, 6 | AC, IA, PS | SecurityArchitect |
| Vulnerability management | 7 | RA, SI | SecurityArchitect |
| Audit log management | 8 | AU | ComplianceOfficer + SREEngineer |
| Email & web protections | 9 | SC, SI | UIUXEngineer + SecurityArchitect |
| Malware defenses | 10 | SI, SC | SREEngineer + SecurityArchitect |
| Data recovery | 11 | CP | SREEngineer |
| Network management & monitoring | 12, 13 | SC, SI, AU | PlatformArchitect + SREEngineer |
| Awareness & training | 14 | AT | ComplianceOfficer |
| Service provider management | 15 | SR, SA, CA | ComplianceOfficer |
| Application security | 16 | SA, SI, RA | SecurityArchitect + FullstackEngineer |
| Incident response | 17 | IR | ComplianceOfficer + FullstackEngineer |
| Penetration testing | 18 | CA, RA | SecurityArchitect |

## 3. Customer audit response playbook

When a customer asks the platform's compliance team for evidence
mapped to a control, the workflow is:

1. **Identify the framework** the customer uses (SOC 2, ISO 27001,
   NIST 800-53, CIS v8, custom).
2. **Translate** the customer's control references to the platform's
   framework mappings (this matrix + the framework docs).
3. **Pull** the relevant evidence records from the Compliance service
   for the customer's tenant.
4. **Generate** an evidence bundle (§7 of
   [`evidence-collection.md`](./evidence-collection.md)) signed by
   the platform.
5. **Hand off** to the customer's GRC interface or to a human auditor.
6. **Log** the request and delivery for our own audit trail.

The Compliance service UI exposes a "respond to audit" workflow that
walks a compliance officer through these steps.

## 4. SOC 2 / ISO 27001 — readiness notes

While the v1 platform targets NIST 800-53 Moderate as its primary
framework, the most common customer-facing audit requests are **SOC 2
Type II** and **ISO 27001**. The mapping is:

| SOC 2 Trust Service Criteria | ISO 27001 Annex A | CIS v8 | NIST 800-53 |
|---|---|---|---|
| CC1 (Control Environment) | A.5 | (process) | PM family |
| CC2 (Communication & Info) | A.5, A.6 | 3, 14 | PM, AT |
| CC3 (Risk Assessment) | A.6 | 18 | RA family |
| CC4 (Monitoring) | A.8, A.9 | 8, 13 | CA, SI, AU |
| CC5 (Control Activities) | A.5–A.18 | 4–18 | All |
| CC6 (Logical & Physical Access) | A.5, A.8, A.9 | 5, 6, 12 | AC, IA, PE |
| CC7 (System Operations) | A.8, A.12, A.13 | 7, 8, 10, 11 | AU, CP, SI, MA |
| CC8 (Change Management) | A.8, A.12, A.14 | 4, 16 | CM, SA |
| CC9 (Risk Mitigation) | A.6 | 3, 15 | RA, SR |
| C (Confidentiality) | A.8 | 3 | SC, PM |
| P (Processing Integrity) | A.8, A.14 | 7, 16 | SI, SA |
| A (Availability) | A.11, A.17 | 11 | CP, PE |
| PI (Privacy) — optional | A.18 | (privacy overlay) | PM-18 to PM-32 |

The Compliance service is structured so that adding a SOC 2 or ISO
27001 mapping is a Sprint 2 follow-up: it is largely a
framework-to-control mapping table, plus evidence format adjustments
(OSCAL for SOC 2 trust criteria, etc.).

### 4.1 ISO 27001 Statement of Applicability (SoA)

The platform will publish an SoA as a Sprint 2 deliverable. The
structure is:

- All Annex A controls listed.
- Applicability (Yes / No) per control.
- Justification for "No".
- Implementation status per control.
- Reference to the relevant compliance document section.
- Reference to the platform's evidence.

## 5. FedRAMP and federal — readiness notes

The platform is *not* FedRAMP-authorized in v1, but the
[`nist-800-53.md`](./nist-800-53.md) document maps the platform to
NIST 800-53 Rev. 5, which is the basis of FedRAMP. A future FedRAMP
Moderate authorization would require:

- **FIPS 140-3 validated cryptography** for all data-in-transit and
  data-at-rest cryptography (see SC-13(1)).
- **Continuous monitoring** submission to the PMO (CA-7).
- **US-only data residency** for federal customers.
- **Stronger incident response** SLAs (1 h to US-CERT for confirmed
  incidents per IR-6).
- **OSCAL-formatted** SSP, SAP, SAR, POA&M, and continuous monitoring
  artefacts.

A FedRAMP authorization is a significant body of work; tracked as a
v2+ roadmap item.

## 6. GDPR / privacy — readiness notes

The platform is designed to support GDPR customers. The relevant
controls are in the PM-18 to PM-32 family. Specific commitments:

- **Data residency** — EU customers can opt into EU-only data
  processing. The platform operates EU regions (e.g., eu-central-1,
  eu-west-1) with no cross-region replication of EU customer data
  outside the EU.
- **Data subject rights** — the platform supports data access,
  rectification, erasure, portability, restriction, and objection
  workflows (§12 of [`evidence-collection.md`](./evidence-collection.md)).
- **Records of processing activities** — the platform maintains a
  controller-side RoPA for its own processing, and provides
  processor-side records to its customers.
- **Sub-processor disclosure** — sub-processors are listed in the
  DPA.
- **Breach notification** — 72 h regulator notification, customer
  notification per DPA.

## 7. PCI DSS 4.0 — readiness notes

The platform is *not* a payment processor; the customer's PCI scope
depends on how they integrate the platform. For customers in CDE
scopes, the platform provides:

- **Network segmentation** evidence (CIS 12, SC-7, AC-4).
- **Access control** evidence (CIS 5, 6, AC, IA).
- **Audit log** evidence (CIS 8, AU family).
- **Vulnerability management** evidence (CIS 7, RA, SI-2).
- **Cryptographic key management** evidence (SC-12, SC-13).

For customers who route card data through the platform, additional
controls apply; tracked as a v1.1 enhancement.

## 8. Customer Trust Portal contents

The platform's public-facing Trust Portal (`/trust`) includes:

- SOC 2 Type II report (annual, when available).
- ISO 27001 certificate (when available).
- CSA STAR submission.
- Pen-test summary (annual).
- Sub-processor list.
- Privacy policy + DPA.
- Security overview.
- Compliance status badges (live, pulled from the Compliance service).
- Architecture diagram.
- Status page.
- `security.txt` and responsible disclosure policy.

## 9. Open questions (Sprint 1)

1. **SOC 2 Type II** target window: 6 months post-GA? 12 months?
2. **ISO 27001** certification scope: just the platform, or also the
   in-platform customer evidence flows?
3. **GDPR DPA** template: do we have one ready, or do we need legal
   review?
4. **OSCAL** adoption: is it required by our first federal prospect?
   (Strongly recommended; should be a Sprint 2 deliverable.)
5. **Customer Trust Portal** hosting: separate from the product
   codebase (e.g., static site), or part of the Compliance service UI?
