# Security Policy

The AI-DevSecOps Command Center is a security-sensitive system. We take the
security of this project — and of every deployment of it — seriously.

## Supported versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

When 1.0 is released we will formalize an LTS matrix in this file.

## Reporting a vulnerability

**Please do not file public GitHub issues for exploitable vulnerabilities.**

Use one of the following private channels:

1. **GitHub Security Advisories** (preferred):
   <https://github.com/aionrs/ai-devsecops-command-center/security/advisories/new>
2. **Email**: `security@aionrs.local` (PGP key in `docs/security/pgp-key.asc`)

We acknowledge reports within **2 business days** and aim to provide a triage
update within **5 business days**.

### What to include

- A clear description of the vulnerability and its impact.
- Affected versions / commits / images.
- Reproduction steps, proof-of-concept code, or a screenshot.
- Any known workarounds.
- Whether you intend to disclose publicly, and your preferred timeline.

### What to expect

1. **Triage** (≤ 5 business days): we confirm the issue, scope impact, and
   assign a severity (CVSS v3.1).
2. **Fix development**: we develop a fix privately. Critical issues are
   prioritized; the timeline is discussed with the reporter.
3. **Coordinated disclosure**: we agree on a disclosure date with the
   reporter. Default embargo is **90 days** from acknowledgment, or sooner
   if a fix is ready.
4. **Public disclosure**: we publish a security advisory on GitHub, plus a
   CVE request via GitHub Security Advisories.
5. **Credit**: reporters are credited in the advisory (unless they prefer
   anonymity).

## Hardening recommendations

These are baseline expectations for any production deployment. They live in
detail in [`docs/security/`](./docs/security/) but the minimums are:

- **TLS 1.2+ everywhere.** No plaintext service-to-service traffic.
- **Secrets in a real secret manager.** Never `.env` files in production.
- **Network policy**: services should be reachable only over the internal
  network. The frontend is the only public surface.
- **Least-privilege RBAC**: every user has the minimum role required.
- **Audit log retention ≥ 365 days**, with off-host backup.
- **Daily encrypted backups** of the database; tested restore quarterly.
- **Dependency updates**: Dependabot is enabled; review PRs weekly.
- **SBOM generated on every release** and tracked in a vulnerability scanner.
- **Runtime scanning**: deploy with an eBPF / sandbox runtime in production
  (e.g. Cilium + gVisor or similar).

## Security architecture

See [`docs/architecture/security-model.md`](./docs/architecture/security-model.md)
for the full security model: auth, RBAC, multi-tenant isolation, threat model,
and trust boundaries.

## Acknowledgements

We thank the security community. Past reporters are listed in
[`docs/security/hall-of-fame.md`](./docs/security/hall-of-fame.md).
