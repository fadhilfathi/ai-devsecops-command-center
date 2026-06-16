# Security Policy

> **Status:** Active
> **Owner:** GitOpsManager (`@aicc/gitops-manager` — see [`CODEOWNERS`](.github/CODEOWNERS))
> **Auto-updated:** Yes — sections between `<!-- BEGIN:auto -->` and `<!-- END:auto -->` markers are managed by `.github/workflows/security.yml`. Do not hand-edit inside the fence. Sections outside the fence are human-maintained.

This document describes how security vulnerabilities are handled in
**AI-DevSecOps Command Center**, both for users of the platform and
for maintainers contributing to the codebase.

---

## Table of contents

1. [Supported versions](#supported-versions)
2. [Vulnerability disclosure](#vulnerability-disclosure)
3. [Reporting process](#reporting-process)
4. [Response targets (SLA)](#response-targets-sla) — *auto-managed*
5. [Automation contract](#automation-contract) — *auto-managed*
6. [Hardening baseline](#hardening-baseline)
7. [Acknowledgements](#acknowledgements)

---

## Supported versions

We follow a **rolling supported window**: the latest minor release
on `main` plus the two prior minor releases receive security
backports. Anything older is end-of-life (EOL) and will not receive
patches.

| Release line | Status            | Security updates |
| ------------ | ----------------- | ---------------- |
| `main`       | Active development| Yes              |
| `0.1.x`      | Supported         | Yes              |
| `0.0.x`      | EOL (pre-alpha)   | No               |

<!-- BEGIN:auto:supported-versions -->
> *This row is auto-generated from the latest GitHub release tags.
> Source: `.github/workflows/security.yml` job `sync-supported-versions`.*
<!-- END:auto:supported-versions -->

When we cut `0.2.0`, `0.0.x` will move to EOL and a new row will
appear here automatically.

---

## Vulnerability disclosure

We follow **coordinated disclosure** with a default **90-day
embargo window** from the time we acknowledge receipt. This is
consistent with the
[CNCF Security TAG's coordinated disclosure guidelines](https://github.com/cncf/tag-security/blob/main/security-disclosure.md)
and Google's
[Project Zero disclosure policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html).

What that means in practice:

- **You** report privately to us (see below).
- **We** acknowledge within the SLA targets in the next section.
- **We** develop a fix in a private fork and run our internal
  test suite.
- **We** disclose publicly on release day, crediting the reporter
  in [`CHANGELOG.md`](CHANGELOG.md) and the GitHub Security Advisory.

If a vulnerability is being actively exploited in the wild
("0-day"), we accelerate the disclosure timeline and may
pre-announce a fix date to downstream consumers.

---

## Reporting process

### How to report

**Preferred:** GitHub private vulnerability reporting
([`Security` tab → `Report a vulnerability`](../../security/advisories/new))

**Fallback:** Email `security@ai-devsecops-command-center.example`
(GPG key: see [`docs/security/pgp-key.asc`](docs/security/pgp-key.asc)
when published). *Replace `example` with the real domain once DNS
is live.*

**Do NOT:**

- File a public issue.
- Discuss the vulnerability on social media, Discord, Slack, or
  any public channel.
- Open a pull request with a fix (this leaks the vulnerability
  prematurely).

### What to include

Please include as much of the following as you can:

- Affected component(s) and version(s) (e.g. `@aicc/auth@0.1.2`)
- Reproduction steps or a proof-of-concept
- Impact assessment (what can an attacker do?)
- Your name/handle for the credits section (or "anonymous")
- Whether you'd like to be informed of the disclosure date in
  advance

### What happens next

1. **Acknowledgement** — within the SLA window for the severity
   (see below).
2. **Triage** — we confirm the bug, assign a severity, and
   identify the affected versions.
3. **Fix development** — on a private branch.
4. **Pre-disclosure notification** — sent to reporters and
   downstream consumers registered via
   [`SECURITY-NOTIFY@example`](mailto:SECURITY-NOTIFY@example).
5. **Public disclosure** — coordinated with the reporter; minimum
   7 days' notice unless 0-day.
6. **Post-mortem** — published for Critical and High findings.

---

## Response targets (SLA)

<!-- BEGIN:auto:sla -->
> *This SLA table is auto-generated from `.github/workflows/security.yml`
> job `sync-sla`. To change a target, update the workflow constants
> and the bot will re-render this block. Last sync: 2026-06-16.*

| Severity | Acknowledge | Triage complete | Patch released | Public disclosure |
| -------- | ----------- | --------------- | -------------- | ----------------- |
| Critical | ≤ 24 h      | ≤ 48 h          | ≤ 7 d          | ≤ 90 d from ack  |
| High     | ≤ 48 h      | ≤ 5 d           | ≤ 30 d         | ≤ 90 d from ack  |
| Medium   | ≤ 5 d       | ≤ 15 d          | ≤ 60 d         | ≤ 90 d from ack  |
| Low      | ≤ 10 d      | ≤ 30 d          | Next minor     | ≤ 90 d from ack  |

Severity bands are mapped from CVSS v3.1 base scores:

- **Critical:** 9.0 – 10.0
- **High:** 7.0 – 8.9
- **Medium:** 4.0 – 6.9
- **Low:** 0.1 – 3.9
<!-- END:auto:sla -->

These are **target** windows, not hard guarantees. We will report
on missed SLAs in our quarterly transparency report.

---

## Automation contract

<!-- BEGIN:auto:automation -->
> *This section is auto-generated from `.github/workflows/security.yml`
> and the runbook at [`docs/runbooks/security-automation.md`](docs/runbooks/security-automation.md).*

The following GitOps workflows are owned by the GitOpsManager role
and operate on this repository:

| Workflow                                       | Trigger                            | Action                                           |
| ---------------------------------------------- | ---------------------------------- | ------------------------------------------------ |
| `.github/workflows/security.yml` (job `sbom-commit`) | push to `main` / daily 03:00 UTC  | Generates CycloneDX + SPDX SBOMs and commits them to [`security/sboms/`](security/sboms/) |
| `.github/workflows/security.yml` (job `vuln-report`)  | `security.vulnerability.detected.v1` event | Appends findings to [`security/vulns/<date>.json`](security/vulns/) (NDJSON) |
| `.github/workflows/security.yml` (job `weekly-digest`) | Mondays 06:00 UTC                 | Aggregates the prior 7 days into [`security/vulns/weekly-<ISO-week>.md`](security/vulns/) |
| `.github/workflows/security-issue.yml`          | `repository_dispatch` (type `critical-cve-detected`) | Opens a deduplicated GitHub issue labelled `security` + `severity:critical` |
| `.github/workflows/release.yml` (job `attach-sbom`)  | `git tag v*.*.*`                  | Attaches the latest SBOM artifacts to the GitHub Release |

All automation operates under the `github-actions[bot]` identity
with the minimum required `permissions:` block declared in each
workflow. See [`docs/runbooks/security-automation.md`](docs/runbooks/security-automation.md)
for the operator runbook.
<!-- END:auto:automation -->

---

## Hardening baseline

These are the **non-negotiable** security controls we ship with
every release. They are enforced by CI; you cannot merge a PR that
breaks them.

- **No secrets in source** — pre-commit hook (`.husky/pre-commit`)
  runs `gitleaks` on staged files. CI runs `gitleaks` again on the
  full tree.
- **Signed commits** — required for the default branch. See
  [`CONTRIBUTING.md`](CONTRIBUTING.md#signing-commits).
- **Branch protection** — `main` requires 2 reviews, all CI
  checks green, and no force-push.
- **Dependency pinning** — all dependencies are pinned in
  `pnpm-lock.yaml`. Renovate/Dependabot opens PRs for upgrades;
  see [`.github/dependabot.yml`](.github/dependabot.yml).
- **SBOM on every release** — see
  [Automation contract](#automation-contract).
- **CVE monitoring** — daily scan of all `@aicc/*` packages; see
  [Automation contract](#automation-contract).
- **Container image scanning** — `trivy` runs in CI on every
  built image. Critical CVEs block merge.

For the full threat model, see
[`docs/architecture/security-model.md`](docs/architecture/security-model.md)
(drafted; will be replaced by the SecurityArchitect's authoritative
version).

---

## Acknowledgements

We thank the following reporters and projects (most recent first):

- *Awaiting first coordinated disclosure report.*

If you report a vulnerability and would like to be credited here,
indicate so in your report. Otherwise we will anonymise the entry.

---

*This document is licensed under
[CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).*
