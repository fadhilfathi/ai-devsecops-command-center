# syntax=docker/dockerfile:1.7
# -----------------------------------------------------------------------------
# AionRs SBOM Pipeline service — production container
#
# Two-stage build:
#   1) builder — install Python deps into a clean virtualenv
#   2) runtime — copy the venv, install Syft via the official
#                installer, and ship only what's needed at runtime.
# -----------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11
ARG SYFT_VERSION=1.6.0

FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip wheel \
    && /opt/venv/bin/pip install /build/src

# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG SYFT_VERSION=1.6.0

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=4007 \
    HOST=0.0.0.0 \
    PATH="/opt/venv/bin:${PATH}" \
    SYFT_BINARY=/usr/local/bin/syft

# Syft ships as a single statically-linked Go binary. The official
# installer pins by version so we don't depend on apt repos that
# lag behind upstream releases.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        tini \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin v${SYFT_VERSION} \
    && syft version \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user.
RUN groupadd --system --gid 1001 aionrs \
    && useradd --system --uid 1001 --gid aionrs --shell /sbin/nologin aionrs \
    && mkdir -p /var/lib/aionrs/sbom-data \
    && chown -R aionrs:aionrs /var/lib/aionrs

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/src /opt/sbom-pipeline/src

USER aionrs
WORKDIR /opt/sbom-pipeline

EXPOSE 4007

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4007/healthz', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "sbom_pipeline.main", "--host", "0.0.0.0", "--port", "4007"]

LABEL org.opencontainers.image.title="aionrs-sbom-pipeline" \
      org.opencontainers.image.description="Syft-wrapped SBOM generation, analysis, and storage service (CycloneDX + SPDX)." \
      org.opencontainers.image.source="https://github.com/aionrs/aionrs-command-center" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="AionRs" \
      io.aionrs.component="sbom-pipeline" \
      io.aionrs.sprint="S2" \
      io.aionrs.task="S2.1"
