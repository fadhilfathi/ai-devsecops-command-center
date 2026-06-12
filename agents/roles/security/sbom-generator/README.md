# SBOM Generator — `agents/roles/security/sbom-generator`

> **Sprint 2 / S2.1** — Syft-wrapped Python service that produces
> software bills-of-materials (SBOMs) for any artifact the platform
> encounters. Runs as a FastAPI HTTP service on **port 4007** and
> participates in the AionRs event bus as a security domain agent.

The service is a thin, opinionated wrapper around the
[Anchore Syft](https://github.com/anchore/syft) CLI. It exposes a
small, well-typed HTTP surface, normalises Syft's JSON output to an
internal SBOM model, and re-serialises that model to **CycloneDX 1.5
(JSON + XML)** and **SPDX 2.3 (JSON + tag:value)**.

## Highlights

- **One binary, many sources** — Docker / OCI images, Git
  repositories, local filesystems, single files, archives, and
  registry catalogs.
- **Multiple output formats in a single request** — ask for
  `cyclonedx-json` and `spdx-json` in the same call.
- **Bounded concurrency** — global `Semaphore` (default 4) and a
  per-request timeout (default 600s).
- **Event bus aware** — publishes `sbom.generated` events to NATS
  (or Redis Streams) and can be driven by `sbom.generate` requests on
  the bus.
- **Observability first** — `/healthz`, `/readyz`, `/metrics`
  (Prometheus), structured JSON logs to stdout.
- **Tenant aware** — `X-Tenant-Id` header is plumbed through into
  the produced SBOM metadata.
- **Fail-safe** — bus publish errors never break a successful scan;
  Syft execution errors carry an actionable error code.

## Quick start

```bash
# install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# install the package in editable mode
python3 -m pip install -e .[dev]

# start the service
./scripts/run-local.sh
```

In another terminal:

```bash
curl -fsS http://127.0.0.1:4007/healthz | jq .

curl -fsS -X POST http://127.0.0.1:4007/v1/sbom/quick \
    -H 'Content-Type: application/json' \
    -d '{"source":"nginx:1.25","format":"cyclonedx-json"}' | jq .components_count
```

## Container

```bash
./scripts/build.sh                                # → aionrs/sbom-generator:dev
docker run --rm -p 4007:4007 aionrs/sbom-generator:dev
```

The image ships with Syft `1.6.0` (override with `--build-arg
SYFT_VERSION=…`) and runs as a non-root user (`aionrs:1001`).

## HTTP API

| Method | Path                          | Purpose                              |
|--------|-------------------------------|--------------------------------------|
| GET    | `/healthz`                    | Liveness + syft version + bus status |
| GET    | `/readyz`                     | Readiness probe                      |
| GET    | `/metrics`                    | Prometheus exposition                |
| GET    | `/v1/sbom/formats`            | List output formats                  |
| GET    | `/v1/sbom/source-kinds`       | List supported source types          |
| POST   | `/v1/sbom/generate`           | Generate SBOM (full payload)         |
| POST   | `/v1/sbom/analyze`            | Alias of `/generate`                 |
| POST   | `/v1/sbom/quick`              | Simplified `{source, format}` body   |

### Full payload (`/v1/sbom/generate`)

```json
{
  "source": {
    "type": "git-repository",
    "value": "https://github.com/aionrs/aionrs-command-center.git"
  },
  "formats": ["cyclonedx-json", "spdx-json"],
  "exclude_paths": [".git", "node_modules"],
  "include_dev_dependencies": false,
  "tenant_id": "tenant-1"
}
```

### Quick payload (`/v1/sbom/quick`)

```json
{ "source": "nginx:1.25", "format": "cyclonedx-json" }
```

The quick endpoint infers `source.type` from the value (image → `docker-image`,
`https://` → `git-repository`, `*.tar*` → `archive`, `/` → `directory`).

## Source kinds

| `type`            | Description                                           | Example                                       |
|-------------------|-------------------------------------------------------|-----------------------------------------------|
| `directory`       | Local filesystem directory                            | `/var/lib/myapp`                              |
| `file`            | Single file                                           | `/var/lib/myapp/Pipfile`                      |
| `docker-image`    | Container image reference                             | `nginx:1.25`                                  |
| `oci-image`       | OCI image fetched by digest                           | `ghcr.io/aionrs/api:v1.0.0`                   |
| `git-repository`  | Git repo (https/git/ssh/file)                         | `https://github.com/aionrs/aionrs.git`        |
| `archive`         | Tarball / zip                                         | `https://example.com/release.tar.gz`          |
| `registry`        | Enumerate a registry catalog                          | `https://registry.example.com`                |

## Output formats

| `format`           | Spec          | Media type                       |
|--------------------|---------------|----------------------------------|
| `cyclonedx-json`   | CycloneDX 1.5 | `application/vnd.cyclonedx+json` |
| `cyclonedx-xml`    | CycloneDX 1.5 | `application/vnd.cyclonedx+xml`  |
| `spdx-json`        | SPDX 2.3      | `application/spdx+json`          |
| `spdx-tag-value`   | SPDX 2.3      | `text/spdx`                      |
| `syft-json`        | Syft native   | `application/json`               |

## Event bus

The agent subscribes to and publishes on a configurable subject
prefix (default `aionrs.security.sbom`):

| Subject                                    | Direction | Payload kind           |
|--------------------------------------------|-----------|------------------------|
| `aionrs.security.sbom.requests`            | inbound   | `GenerateRequest` JSON |
| `aionrs.security.sbom.results`             | outbound  | `{status, request_id}` |
| `aionrs.security.sbom.events`              | outbound  | `agent.ready`, `agent.stopping`, `sbom.generated` |

The bus implementation is pluggable — `NATSClient` (default) or
`InMemoryBus` (used by tests and the `--bus-url=memory://` flag).

## Configuration

| Env var                  | Default                 | Notes                                  |
|--------------------------|-------------------------|----------------------------------------|
| `PORT`                   | `4007`                  |                                        |
| `HOST`                   | `0.0.0.0`               |                                        |
| `SYFT_BINARY`            | `syft`                  | Absolute path or `$PATH` lookup        |
| `BUS_URL`                | `nats://localhost:4222` | Use `memory://` to disable the bus     |
| `BUS_SUBJECT_PREFIX`     | `aionrs.security.sbom`  |                                        |
| `SBOM_WORKSPACE`         | `/var/lib/aionrs/sbom-workspace` | Working dir for scans     |
| `REQUEST_TIMEOUT_SECONDS`| `600`                   | Per-syft invocation timeout            |
| `MAX_CONCURRENT_SCANS`   | `4`                     | Global concurrency cap                 |
| `DEFAULT_FORMAT`         | `cyclonedx-json`        |                                        |
| `REQUIRE_AUTH`           | `false`                 | When `true`, requires `Authorization: Bearer …` + `X-Tenant-Id` |

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       SBOM Generator service                       │
│                                                                    │
│   HTTP request ──► FastAPI (service.py) ──► SBOMGeneratorAgent     │
│                                              │                     │
│                                              ▼                     │
│                                          SyftRunner (syft.py)      │
│                                              │                     │
│                       ┌──────────────────────┼──────────────────┐  │
│                       │                      ▼                  │  │
│   asyncio.subprocess  │              Syft CLI (binary)          │  │
│                       │                      │                  │  │
│                       │                      ▼                  │  │
│                       │              raw Syft JSON                │  │
│                       │                      │                  │  │
│                       │                      ▼                  │  │
│                       │           normalize_syft_output()        │  │
│                       │                      │                  │  │
│                       │                      ▼                  │  │
│                       │              internal SBOM model         │  │
│                       │                      │                  │  │
│                       │     ┌────────────────┼────────────────┐ │  │
│                       │     ▼                ▼                ▼ │  │
│                       │  CycloneDX-JSON  CycloneDX-XML  SPDX-…   │  │
│                       └────────────────────────────────────────┘  │
│                                              │                     │
│                                              ▼                     │
│                                       Bus publish + telemetry     │
└────────────────────────────────────────────────────────────────────┘
```

## Development

```bash
# format + lint
ruff check src tests
ruff format src tests

# type check
mypy src

# test
pytest
pytest --cov=src/sbom_generator --cov-report=term-missing
```

## File layout

```
sbom-generator/
├── README.md
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
├── src/sbom_generator/
│   ├── __init__.py
│   ├── __main__.py
│   ├── agent.py
│   ├── service.py
│   ├── syft.py
│   ├── output.py
│   ├── config.py
│   ├── telemetry.py
│   ├── errors.py
│   └── models/
│       ├── __init__.py
│       ├── request.py
│       ├── response.py
│       └── sbom.py
├── tests/
│   ├── conftest.py
│   ├── test_sbom_model.py
│   ├── test_output.py
│   ├── test_request_model.py
│   ├── test_service.py
│   ├── test_agent_and_syft.py
│   ├── test_telemetry.py
│   └── fixtures/
│       ├── sample-syft.json
│       ├── sample-cyclonedx.json
│       └── sample-spdx.spdx
├── scripts/
│   ├── build.sh
│   ├── run-local.sh
│   └── generate.sh
├── docs/
│   ├── openapi.yaml
│   └── ARCHITECTURE.md
└── examples/
    └── requests.sh
```

## License

Apache-2.0 — see [`LICENSE`](../../LICENSE).
