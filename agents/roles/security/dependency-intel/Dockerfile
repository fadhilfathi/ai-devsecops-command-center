# ---- runtime ----
FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OTEL_SERVICE_NAME=dependency-intel \
    OTEL_SERVICE_VERSION=0.1.0

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app && useradd --system --gid app --home /app app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# The service writes its graph store under DEP_INTEL_DATA_DIR (default
# ./data, resolved against WORKDIR /app — owned by root). Give the non-root
# runtime user its own writable data dir instead of loosening /app.
RUN mkdir -p /var/lib/dependency-intel && chown -R app:app /var/lib/dependency-intel
ENV DEP_INTEL_DATA_DIR=/var/lib/dependency-intel

USER app

EXPOSE 5003

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:5003/livez',timeout=2).status==200 else 1)"

ENTRYPOINT ["python", "-m", "dependency_intel"]
