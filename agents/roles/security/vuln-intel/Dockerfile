# =============================================================================
# vuln-intel — Vulnerability Intelligence Service
# Sprint 2 deliverable S2.2 — Owner: VulnerabilityIntelligenceAgent
#
# Listens on port 4008. Ingest CVEs from NVD 2.0, GitHub Security Advisories
# (GHSA), and OSV.dev, normalize them to a unified schema, attach EPSS-based
# exploit likelihood scores, and expose the data through a FastAPI surface
# for the security-service API layer (S2.5) and the UI (S2.6).
#
# Endpoints (REST):
#   POST /vuln-intel/ingest              on-demand ingestion trigger
#   GET  /vuln-intel/cve/{cve_id}        fetch one normalized CVE
#   POST /vuln-intel/cve/lookup          bulk lookup by IDs
#   POST /vuln-intel/score               re-score a single CVE or batch
#   POST /vuln-intel/match               match vulnerabilities to SBOM
#   GET  /vuln-intel/stats               coverage + cache stats
#   POST /vuln-intel/sync/once           manual NVD/GHSA/OSV pull
#
# Health / observability:
#   GET  /livez      liveness
#   GET  /readyz     readiness (deep checks: cache, source reachability)
#   GET  /metrics    Prometheus metrics
# =============================================================================

# ---- runtime ----
FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OTEL_SERVICE_NAME=vuln-intel \
    OTEL_SERVICE_VERSION=0.1.0

WORKDIR /app

# OS-level deps kept minimal — vuln-intel is pure-Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user
RUN groupadd --system app && useradd --system --gid app --home /app app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Drop privileges
USER app

EXPOSE 4008 9098

# Healthcheck — uvicorn exposes /livez on the app port
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:4008/livez',timeout=2).status==200 else 1)"

ENTRYPOINT ["python", "-m", "vuln_intel"]
