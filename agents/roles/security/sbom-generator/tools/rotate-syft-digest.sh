#!/usr/bin/env bash
# =============================================================================
# tools/rotate-syft-digest.sh
# =============================================================================
# Idempotent, dry-run-friendly helper to rotate the pinned Syft image digest
# in agents/roles/security/sbom-generator/Dockerfile.
#
# Spec owner: SecurityArchitect (slot 019ebae2-9de4-7223-9920-60866bc88d45).
# Locked: 2026-06-12 as part of the S2.8 hardening hotfix.
#
# What it does:
#   1. Resolves the upstream digest for the given Syft tag (default v1.6.0)
#      via the Docker Hub registry API (no auth required for public images).
#   2. Validates the new digest with `cosign verify` (keyless) against the
#      Anchore OIDC identity if `cosign` is installed; otherwise skips with
#      a warning. Verification can be forced with --require-verify.
#   3. Rewrites the SYFT_DIGEST ARG in the Dockerfile. If the new digest
#      matches the existing one, the script exits 0 without changes.
#   4. Optionally re-runs the SS-01..SS-07 security test suite to confirm
#      the rotation does not regress the SSRF defense.
#   5. Prints a one-line git diff for review.
#
# Usage:
#   tools/rotate-syft-digest.sh [--tag v1.6.0] [--dry-run] \
#       [--require-verify] [--run-tests] [--dockerfile PATH]
#
# Canary rotation (7-day schedule, manual):
#   Day 0: --dry-run (confirm digest + verify locally)
#   Day 1: 10% canary   — bump image tag in staging cluster, observe metrics
#   Day 4: 50% canary   — half traffic
#   Day 7: 100% rollout — full prod, mark old digest as tombstone
#
# When the rotation is approved, also update:
#   - agents/roles/security/sbom-generator/Dockerfile (this script does it)
#   - agents/roles/security/sbom-generator/deploy/kubernetes.yaml
#     (the cosign-verify initContainer pins the same digest for verification)
#   - the upstream ``syft_version`` label in the Deployment
#   - any pinned-digest references in observability dashboards
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults & arg parsing
# ---------------------------------------------------------------------------

SYFT_TAG="v1.6.0"
DRY_RUN=0
REQUIRE_VERIFY=0
RUN_TESTS=0
DOCKERFILE_PATH="agents/roles/security/sbom-generator/Dockerfile"
KUBERNETES_PATH="agents/roles/security/sbom-generator/deploy/kubernetes.yaml"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            SYFT_TAG="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --require-verify)
            REQUIRE_VERIFY=1
            shift
            ;;
        --run-tests)
            RUN_TESTS=1
            shift
            ;;
        --dockerfile)
            DOCKERFILE_PATH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage
            ;;
    esac
done

log() { printf '[rotate-syft-digest] %s\n' "$*" >&2; }
die() { printf '[rotate-syft-digest] FATAL: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
[[ -f "$DOCKERFILE_PATH" ]] || die "Dockerfile not found: $DOCKERFILE_PATH"

# ---------------------------------------------------------------------------
# 1. Resolve upstream digest for the manifest list
# ---------------------------------------------------------------------------

resolve_digest() {
    local tag="$1"
    # Docker Hub registry manifest endpoint. This returns the manifest-list
    # digest, which is what kubelet resolves to a per-arch image.
    local url="https://registry-1.docker.io/v2/anchore/syft/manifests/${tag}"
    local accept="application/vnd.docker.distribution.manifest.list.v2+json"
    local auth
    # Fetch a bearer token (Docker Hub allows anonymous pulls of public images).
    auth=$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:anchore/syft:pull" \
        | grep -o '"token":"[^"]*"' | sed 's/"token":"\(.*\)"/\1/') \
        || die "failed to fetch Docker Hub bearer token"
    # The response body is the manifest list. We don't need to parse it; the
    # digest is in the ``Docker-Content-Digest`` header.
    local digest
    digest=$(curl -fsSL -H "Authorization: Bearer ${auth}" \
        -H "Accept: ${accept}" \
        -I "${url}" \
        | tr -d '\r' \
        | grep -i '^docker-content-digest:' \
        | awk '{print $2}') \
        || die "failed to fetch manifest digest for anchore/syft:${tag}"
    [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || die "digest format invalid: $digest"
    printf '%s' "$digest"
}

log "Resolving digest for anchore/syft:${SYFT_TAG} ..."
NEW_DIGEST=$(resolve_digest "$SYFT_TAG")
log "Upstream digest: ${NEW_DIGEST}"

# ---------------------------------------------------------------------------
# 2. cosign verify (if available / required)
# ---------------------------------------------------------------------------

if command -v cosign >/dev/null 2>&1; then
    log "cosign found; verifying keyless signature for ${NEW_DIGEST} ..."
    if ! cosign verify \
        --certificate-identity-regexp '^https://github.com/anchore/syft/\.github/workflows/release\.yml@refs/tags/v.*$' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "anchore/syft@${NEW_DIGEST}" >/dev/null 2>&1; then
        [[ "$REQUIRE_VERIFY" -eq 1 ]] && die "cosign verify FAILED for ${NEW_DIGEST}"
        log "WARN: cosign verify did not confirm; continuing (--require-verify not set)"
    else
        log "cosign verify: OK"
    fi
elif [[ "$REQUIRE_VERIFY" -eq 1 ]]; then
    die "cosign not installed but --require-verify was set"
else
    log "WARN: cosign not installed; skipping signature verification (install from https://docs.sigstore.dev/cosign/installation/)"
fi

# ---------------------------------------------------------------------------
# 3. Rewrite the Dockerfile (idempotent)
# ---------------------------------------------------------------------------

CURRENT_DIGEST=$(grep -E '^ARG[[:space:]]+SYFT_DIGEST=' "$DOCKERFILE_PATH" \
    | head -1 \
    | sed -E 's/^ARG[[:space:]]+SYFT_DIGEST=//') \
    || die "could not parse SYFT_DIGEST from $DOCKERFILE_PATH"

if [[ "$CURRENT_DIGEST" == "$NEW_DIGEST" ]]; then
    log "Digest is already up to date: ${NEW_DIGEST}"
    log "Nothing to do."
    exit 0
fi

log "Digest change: ${CURRENT_DIGEST} -> ${NEW_DIGEST}"

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: would update $DOCKERFILE_PATH"
    log "DRY-RUN: would update $KUBERNETES_PATH (cosign-verify initContainer)"
    exit 0
fi

# Replace the ARG line in place. We use a Python one-liner for safety because
# some platforms have a BSD sed that doesn't handle the same syntax as GNU sed.
python3 - "$DOCKERFILE_PATH" "$NEW_DIGEST" <<'PY'
import re
import sys

path, new_digest = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

pattern = re.compile(r"^(ARG\s+SYFT_DIGEST=).*$", re.MULTILINE)
new_text, n = pattern.subn(r"\g<1>" + new_digest, text, count=1)
if n != 1:
    print(f"ERROR: expected to replace exactly 1 ARG SYFT_DIGEST line; got {n}", file=sys.stderr)
    sys.exit(2)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
print(f"Updated {path} -> {new_digest}", file=sys.stderr)
PY

# Also update the cosign-verify initContainer in the Kubernetes manifest so
# the verification digest matches the pinned image.
python3 - "$KUBERNETES_PATH" "$NEW_DIGEST" <<'PY'
import re
import sys

path, new_digest = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

pattern = re.compile(
    r"anchore/syft@sha256:[a-f0-9]{64}",
    re.MULTILINE,
)
new_text, n = pattern.subn("anchore/syft@" + new_digest, text)
if n == 0:
    print(f"ERROR: no anchore/syft@sha256:... reference found in {path}", file=sys.stderr)
    sys.exit(2)
print(f"Updated {n} digest reference(s) in {path}", file=sys.stderr)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_text)
PY

# ---------------------------------------------------------------------------
# 4. Re-run the security test suite (optional)
# ---------------------------------------------------------------------------

if [[ "$RUN_TESTS" -eq 1 ]]; then
    log "Re-running SS-01..SS-07 test suite ..."
    if command -v poetry >/dev/null 2>&1; then
        (cd "$(dirname "$DOCKERFILE_PATH")" && poetry run pytest tests/test_ssrf.py tests/test_request_model.py -k 'ss_07 or test_classify or test_is_private or test_resolve or test_assert_safe or test_allowlist' -v)
    else
        log "WARN: poetry not installed; skipping test run"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Print a one-line diff for review
# ---------------------------------------------------------------------------

log "Diff summary:"
git diff --stat -- "$DOCKERFILE_PATH" "$KUBERNETES_PATH" 2>/dev/null \
    || log "  (not a git checkout, or no changes tracked)"

log "Done. Review the diff, commit on a hotfix branch, and run the canary schedule:"
log "  Day 1: 10% canary"
log "  Day 4: 50% canary"
log "  Day 7: 100% rollout"
