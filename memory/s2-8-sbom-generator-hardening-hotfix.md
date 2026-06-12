---
name: S2.8 SBOM Generator Hardening Hotfix (2026-06-12)
description: 7-item S2.8 hardening hotfix on agents/roles/security/sbom-generator/: T-07 SSRF defense, Syft image digest pin, Pod hardening, NetworkPolicy, cosign-verify, resource limits, volume mounts, rotation script. Branch hotfix/s2.8-sbom-generator-hardening.
type: project
---
# S2.8 SBOM Generator Hardening Hotfix (T-07 + 6 SecurityArchitect items)

## Why this exists
SecurityArchitect (slot `019ebae2-9de4-7223-9920-60866bc88d45`) sent
S2.8 mitigations as a GA blocker for the v1 service. Six items plus
one **question back** that I confirmed was a real gap:

> "The `dev_input` validator strips unsafe URL schemes — does it ALSO
> reject `https://` URLs to internal IPs (RFC 1918, link-local,
> loopback, multicast)?"

The pre-existing `validate_source` in `models/request.py` only stripped
`file://` and had no host/IP validation. Confirmed and committed to fix
it as a 7th item in the same hotfix.

## What's in the PR (branch `hotfix/s2.8-sbom-generator-hardening`)

### 1. T-07 SSRF defense (NEW, was the question back)

- **`src/sbom_generator/security/__init__.py`** + **`security/ssrf.py`**
  - IPv4 CIDR blocklist: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT),
    `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`,
    `192.0.2.0/24` (TEST-NET-1), `192.168.0.0/16`, `198.18.0.0/15`,
    `198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3),
    `224.0.0.0/4` (multicast), `240.0.0.0/4` (reserved),
    `255.255.255.255/32` (broadcast)
  - IPv6 CIDR blocklist: `::/128`, `::1/128`, `::ffff:0:0/96`,
    `64:ff9b::/96`, `100::/64`, `2001::/23`, `2001:db8::/32`,
    `fc00::/7` (ULA), `fe80::/10`, `ff00::/8`
  - Hostname blocklist: `localhost`, `*.localhost`, `*.local`,
    `*.internal`, `*.intranet`, `*.corp`, `*.lan`, `*.home`,
    `*.private`, `*.test`, `*.invalid`, `*.example.*`,
    `metadata.google.internal`, `metadata.azure.com`,
    `instance-data.ec2.internal`
  - Functions: `is_private_ip`, `classify_hostname`, `extract_host`,
    `host_matches_allowlist`, `resolve_and_check` (async,
    `asyncio.getaddrinfo` + `asyncio.wait_for`),
    `assert_safe_target` (top-level orchestrator)
  - Fail-closed on: invalid IP, empty host, DNS timeout, gaierror,
    unexpected exception
- **`src/sbom_generator/models/request.py`**
  - `validate_source` calls `_assert_host_ssrf_safe` for
    `git-repository` / `docker-image` / `oci-image` / `registry`
  - Helper `_extract_git_host` (URL or SCP-style)
  - Helper `_extract_image_host` (handles `10.0.0.5:5000/repo`,
    `[::1]:5000/repo`, `docker.io` default for bare names)
- **`src/sbom_generator/agent.py`**
  - New `_ssrf_check(request)` method runs *after* `validate_source()`
    but *before* `_runner.run(...)` (so DNS rebinding is caught even
    when the model validator accepted a hostname)
  - Emits `sbom.ssrf.blocked` and `sbom.ssrf.error` telemetry events
- **`src/sbom_generator/config.py`**
  - `SsrfConfig` dataclass with `git_host_allowlist`, `default_deny`,
    `dns_timeout_seconds`
  - Defaults: `("github.com", "*.github.com", "gitlab.com",
    "*.gitlab.com", "bitbucket.org", "*.bitbucket.org",
    "git.example.internal")` with `default_deny=True`
  - Env overrides: `SBOM_GENERATOR_GIT_HOST_ALLOWLIST`,
    `SBOM_GENERATOR_SSRF_DEFAULT_DENY`, `SBOM_GENERATOR_SSRF_DNS_TIMEOUT_SECONDS`
- **`src/sbom_generator/errors.py`**
  - New `SsrfBlockedError(ValidationError)` subclass with
    `code = "ssrf_blocked"`, `http_status = 400`
- **`tests/test_request_model.py`** — 9 new parametrized test cases
  (SS-07a..SS-07j)
- **`tests/test_ssrf.py`** (NEW, 250+ lines) — unit tests for the
  security module: `is_private_ip`, `classify_hostname`, `extract_host`,
  `host_matches_allowlist`, `resolve_and_check` (mocked), and
  `assert_safe_target` (mocked)

### 2. Syft image digest pin
- **`Dockerfile`**: rewritten with two stages
  - Stage 1 (`syft-fetcher`): downloads `syft_${VERSION}_linux_amd64.tar.gz`
    + `syft_${VERSION}_checksums.txt` from `github.com/anchore/syft/releases`,
    verifies via `sha256sum -c`, and validates the
    `SYFT_DIGEST` ARG matches `^sha256:[a-f0-9]{64}$` (build fails loudly
    if the digest is empty or a tag)
  - Stage 2 (`runtime`): `COPY --from=syft-fetcher` the verified binary;
    no re-fetch at runtime
- **Pinned digest**: `sha256:c08a4abac5e4abe6dc1939a2b7f12cfa8636f13defecf6476b854f1a0dcc9c84`
  (manifest-list for `anchore/syft:v1.6.0`, resolved via Docker Hub
  registry API 2026-06-12)
- **`tools/rotate-syft-digest.sh`** (NEW, 200+ lines)
  - `--tag`, `--dry-run`, `--require-verify`, `--run-tests`,
    `--dockerfile` flags
  - Resolves upstream digest via the Docker Hub registry bearer-token
    flow (no `crane`/`cosign`/`docker` required for resolve)
  - Verifies via `cosign verify --certificate-identity-regexp
    '^https://github.com/anchore/syft/\.github/workflows/release\.yml@refs/tags/v.*$'
    --certificate-oidc-issuer
    'https://token.actions.githubusercontent.com'` if `cosign` is
    installed; skips with WARN otherwise
  - Rewrites `ARG SYFT_DIGEST=...` in Dockerfile AND
    `anchore/syft@sha256:...` in `deploy/kubernetes.yaml`
  - Prints a one-line `git diff --stat` for review
  - Canary schedule documented in script header:
    Day 1 10% → Day 4 50% → Day 7 100%

### 3. Pod-spec hardening
- **`deploy/kubernetes.yaml`**
  - `runAsUser: 10000` (was 1001) — matches Dockerfile
  - `appArmorProfile: type: Localhost, localhostProfile: sbom-scanner`
    (NEW; cluster operator must load the profile)
  - `runAsGroup: 10000`, `fsGroup: 10000`
  - `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
    `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`
  - Resources: requests 250m/512Mi, limits 2/4Gi
  - Init container `cosign-verify` runs the keyless verify described
    above; requests 50m/64Mi, limits 200m/128Mi, with the same
    non-root/readOnlyRootfs/drop-all-caps posture
  - `topologySpreadConstraints` for zone-spread
  - `PodDisruptionBudget: minAvailable: 1`

### 4. NetworkPolicy
- `default-deny` ingress; only the in-cluster gateway namespace can
  reach port 4007
- Egress limited to:
  - DNS (UDP+TCP 53 to `k8s-app: kube-dns`)
  - Egress proxy (TCP 3128 + 8080 to `egress-proxy` namespace)
  - No other egress; no direct internet

### 5. Resource limits
- See item 3 (Pod spec)

### 6. Volume mounts
- `workspace` (emptyDir, 1Gi) → `/workspace`
- `syft-cache` (emptyDir, 512Mi) → `/var/lib/syft` (NEW volume for
  Syft cache; emptyDir so it doesn't survive Pod restart)
- `work` (PVC, 4Gi, RO) → `/work` (input targets)
- `tmp` (emptyDir.medium=Memory, 256Mi) → `/tmp` (scratch)
- `home` (emptyDir, 64Mi) → `/home/sbomgen`
- New PVC: `sbom-generator-work` (ROX, `standard-ro` storage class)

## Files changed (summary)

- `agents/roles/security/sbom-generator/Dockerfile` (rewritten)
- `agents/roles/security/sbom-generator/deploy/kubernetes.yaml`
  (Pod hardening + cosign-verify initContainer + NetworkPolicy +
  volume layout + PDB)
- `agents/roles/security/sbom-generator/src/sbom_generator/security/__init__.py`
  (NEW)
- `agents/roles/security/sbom-generator/src/sbom_generator/security/ssrf.py`
  (NEW, 250+ lines)
- `agents/roles/security/sbom-generator/src/sbom_generator/config.py`
  (`SsrfConfig` added; `Settings.ssrf` field; `from_env` reads it)
- `agents/roles/security/sbom-generator/src/sbom_generator/errors.py`
  (`SsrfBlockedError` added)
- `agents/roles/security/sbom-generator/src/sbom_generator/models/request.py`
  (SSRF check in `validate_source` + 3 helper methods)
- `agents/roles/security/sbom-generator/src/sbom_generator/agent.py`
  (`_ssrf_check` method; called from `generate`)
- `agents/roles/security/sbom-generator/tests/test_request_model.py`
  (SS-07a..SS-07j test cases added)
- `agents/roles/security/sbom-generator/tests/test_ssrf.py` (NEW)
- `agents/roles/security/sbom-generator/tools/rotate-syft-digest.sh`
  (NEW)

## Open / next steps (S3.x)
- Land the PR against `main` after SecurityArchitect's review
- AppArmor profile `sbom-scanner` must be loaded into each node by the
  cluster operator; not in this repo
- Cluster operator must create the `sbom-generator` namespace and
  apply the manifest
- 7-day canary rotation when the next Syft version lands

## Notes for myself
- `appArmorProfile` is a *container*-level field, not a pod-level field
  in K8s 1.30+; my placement is correct
- The cosign-verify initContainer runs once per Pod start, not per
  scan, so the cost is amortized
- I used `asyncio.getaddrinfo` (not `socket.getaddrinfo`) so the
  resolver is non-blocking; the thread-pool fallback would still
  work but the explicit async API is cleaner
- The async SSRF check only runs for *remote* source kinds
  (GIT_REPOSITORY, DOCKER_IMAGE, OCI_IMAGE, REGISTRY). Local
  sources (DIRECTORY, FILE, ARCHIVE) are never subjected to the
  check, so workspace staging remains fast
- The `default_deny=True` posture means an empty allowlist is treated
  as "reject everything except blocklist-bypassed cases" — actually
  no: empty allowlist means "no allowlist enforcement" (blocklist
  only). The `default_deny` only fires when the allowlist is non-empty
  AND the host is not in it. The k8s env explicitly sets
  `SBOM_GENERATOR_GIT_HOST_ALLOWLIST` to a non-empty value, so
  `default_deny=True` is the effective posture
