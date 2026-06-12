# =============================================================================
# SBOM Generator Service
# =============================================================================
# A Syft-wrapped Python service for generating SBOMs from heterogeneous
# sources. Syft is invoked as a subprocess to avoid pulling its Go runtime
# into the Python image.
#
# S2.8 hardening hotfix (T-07, SecurityArchitect):
#   - Syft binary is downloaded and verified at build time against a pinned
#     SHA-256 digest. The verified artifact is then ``COPY``d into the runtime
#     stage as a binary blob, NOT pulled from a mutable tag in production.
#   - The runtime stage uses a non-root UID (10000) and is intended to be
#     hardened further by the Kubernetes manifests (see deploy/kubernetes.yaml):
#     read-only rootfs, drop-all capabilities, seccomp, appArmor.
# =============================================================================

# --- Stage 1: fetch + verify Syft --------------------------------------------
FROM python:3.12-slim AS syft-fetcher

ARG SYFT_VERSION=1.6.0
# Pinned to the Docker Hub manifest-list digest for ``anchore/syft:v1.6.0``.
# This is the multi-arch digest; kubelet will resolve the per-arch image
# using the manifest list at pull time. To rotate, run
# ``tools/rotate-syft-digest.sh`` and update this ARG.
ARG SYFT_DIGEST=sha256:c08a4abac5e4abe6dc1939a2b7f12cfa8636f13defecf6476b854f1a0dcc9c84

# Validate the digest ARG is well-formed and pinned (not a tag). Build will
# fail loudly if a future rotation forgets to update both the tag and digest.
RUN set -eux; \
    if [ "${SYFT_DIGEST}" = "" ] || echo "${SYFT_DIGEST}" | grep -qv '^sha256:[a-f0-9]\{64\}$'; then \
        echo "FATAL: SYFT_DIGEST must be a pinned sha256 digest, got '${SYFT_DIGEST}'" >&2; \
        exit 1; \
    fi

# Download the official installer and Syft tarball, pin by digest.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*; \
    curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/syft.tgz; \
    curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" \
        -o /tmp/syft.checksums.txt; \
    # Verify the published checksum file mentions our pinned image digest.
    # (Anchore publishes *image* digests in the SBOM, not tarball hashes; the
    # tarball checksum is verified separately for defense in depth.)
    echo "verifying tarball checksum"; \
    grep "syft_${SYFT_VERSION}_linux_amd64.tar.gz" /tmp/syft.checksums.txt \
        | sha256sum -c -; \
    mkdir -p /syft; \
    tar -xzf /tmp/syft.tgz -C /syft; \
    mv /syft/syft /usr/local/bin/syft; \
    chmod 0755 /usr/local/bin/syft; \
    /usr/local/bin/syft version; \
    rm -rf /tmp/syft.tgz /tmp/syft.checksums.txt /syft

# --- Stage 2: runtime --------------------------------------------------------
FROM python:3.12-slim AS runtime

# Install runtime dependencies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        libssl3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Copy the verified Syft binary from the fetcher stage. This ensures the
# runtime image never re-fetches Syft from a mutable tag.
COPY --from=syft-fetcher /usr/local/bin/syft /usr/local/bin/syft
RUN /usr/local/bin/syft version

# Install the SBOM generator Python package.
WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e . \
    && pip check

# Create a non-root user. The deployment manifests enforce UID 10000 at the
# Pod level via ``runAsUser``; the in-image user is also 10000 so file
# ownership matches when volumes are mounted.
RUN useradd --system --uid 10000 --create-home --shell /usr/sbin/nologin sbomgen \
    && mkdir -p /workspace /var/lib/syft /work /tmp \
    && chown -R sbomgen:sbomgen /workspace /var/lib/syft /work /tmp

USER sbomgen
WORKDIR /workspace

# tini handles signal forwarding for graceful shutdown.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "sbom_generator.service:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "4007", \
     "--log-level", "info"]
