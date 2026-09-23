# Security Policy

This document describes how security vulnerabilities are handled in
**AI-DevSecOps Command Center**, for users of the platform and for
contributors to the codebase.

Status: pre-alpha, solo-maintained. Treat all SLAs below as
best-effort targets, not guarantees.

## Supported versions

We follow a **rolling supported window**: the latest minor release
on `main` plus the two prior minor releases receive security
backports. Anything older is end-of-life (EOL) and will not receive
patches.

| Release line | Status             | Security updates |
| ------------ | ------------------ | ---------------- |
| `main`       | Active development | Yes              |
| `0.1.x`      | Supported          | Yes              |
| `0.0.x`      | EOL (pre-alpha)    | No               |

## Reporting a vulnerability

**Preferred:** GitHub private vulnerability reporting — go to the
[`Security` tab → `Report a vulnerability`](../../security/advisories/new)
on this repository. This is free, keeps the report private until a
fix ships, and notifies the maintainer directly.

**Do NOT:**

- File a public issue for a vulnerability.
- Open a pull request with a fix (this leaks the vulnerability
  before a patch is ready).

### What to include

- Affected component(s) and version(s) (e.g. `backend/services/auth@0.1.x`)
- Reproduction steps or a proof-of-concept
- Impact assessment (what can an attacker do?)
- Whether you'd like to be credited (name/handle, or "anonymous")

### What happens next

1. Acknowledgement — best-effort within the targets below.
2. Triage — confirm the bug, assign a severity, identify affected versions.
3. Fix development on a private branch.
4. Public disclosure coordinated with the reporter, crediting them
   (if desired) in [`CHANGELOG.md`](CHANGELOG.md) and a GitHub
   Security Advisory.

### Response targets (best-effort)

Severity bands follow CVSS v3.1 base scores.

| Severity            | Acknowledge | Patch target |
| ------------------- | ----------- | ------------ |
| Critical (9.0–10.0) | 3 days      | Next release |
| High (7.0–8.9)      | 7 days      | Next release |
| Medium (4.0–6.9)    | 14 days     | Best-effort  |
| Low (0.1–3.9)       | 30 days     | Best-effort  |

## Automated security tooling

The following runs automatically on this repository (all free/OSS,
zero-cost — see `.github/workflows/`):

| Workflow                              | What it does                                          |
| ------------------------------------- | ----------------------------------------------------- |
| `.github/workflows/sbom.yml`          | Generates a CycloneDX SBOM on every push/PR to `main` |
| `.github/workflows/codeql.yml`        | Static analysis (CodeQL) for JS/TS and Python         |
| `.github/workflows/scorecard.yml`     | OpenSSF Scorecard supply-chain risk scan              |
| Dependabot (`.github/dependabot.yml`) | Dependency, Docker, and GitHub Actions update PRs     |

For the full threat model, see
[`docs/architecture/security-model.md`](docs/architecture/security-model.md).

## Acknowledgements

We thank the following reporters (most recent first):

- _Awaiting first coordinated disclosure report._

If you report a vulnerability and would like to be credited here,
say so in your report. Otherwise the entry will be anonymised.

---

_This document is licensed under
[CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)._
