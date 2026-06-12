# SBOM Pipeline — `backend/services/sbom-pipeline-service/`

> **Sprint 2 / S2.1** — Syft-wrapped Python service that generates,
> normalizes, analyzes, and stores software bills-of-materials for
> the AionRs security stack. Runs on **port 4007**.

The service is a thin, opinionated wrapper around
[Anchore Syft](https://github.com/anchore/syft). It exposes a small
HTTP surface, persists every SBOM in SQLite (dev) / Postgres (prod),
emits lifecycle events on the bus, and provides a Click CLI for
ad-hoc use.

## Highlights

- **One binary, many sources** via a single `source:` field:
  - `docker:<image:tag>` — `docker:nginx:1.25`
  - `git:<url-or-path>` — `git:https://github.com/foo/bar`
  - `fs:<path>` — `fs:/path/to/project`
  - `lockfile:<file>` — `lockfile:/path/to/package-lock.json`
- **CycloneDX 1.5** and **SPDX 2.3** (JSON + tag-value) outputs.
- **Analyzes** every SBOM: transitive depth, ecosystems, license
  breakdown, total size in bytes.
- **Persists** every SBOM in SQLite (dev) / Postgres (prod) plus a
  filesystem / S3 blob store.
- **Bus-aware** — emits `security.sbom.{generated,failed,analyzed,
  stored}.v1` and consumes `security.sbom.requested.v1`.
- **Click CLI** mirrors the HTTP API: `python -m sbom_pipeline
  generate|analyze|list|get|delete|serve`.
- **Bounded concurrency** (`asyncio.Semaphore`) and per-request
  timeouts (default 600s, 256 MiB stdout cap).
- **OTel + Prometheus** — emits the locked `devsecops_sbom_*` metric
  set agreed with the SRE agent in S2.7.

## Quick start

```bash
# install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# install the package in editable mode
python3 -m pip install -e .[dev]

# start the service (in-memory bus, in-memory store)
SBOM_DB_URL=sqlite+aiosqlite:///:memory: \
SBOM_BUS_URL=memory:// \
python -m sbom_pipeline.cli serve
```

In another terminal:

```bash
ENDPOINT=http://127.0.0.1:4007

curl -fsS $ENDPOINT/healthz | jq .

curl -fsS -X POST $ENDPOINT/sbom/generate \
    -H 'Content-Type: application/json' \
    -d '{"source":"docker:nginx:1.25","format":"cyclonedx-json"}' | jq .sbom_id
```

## Container

```bash
docker build -t aionrs/sbom-pipeline:dev .
docker run --rm -p 4007:4007 aionrs/sbom-pipeline:dev
```

The image ships with Syft `1.6.0` (override with
`--build-arg SYFT_VERSION=…`) and runs as a non-root user
(`aionrs:1001`).

## HTTP API

| Method | Path                | Body / Query                                       | Returns                                                              |
|--------|---------------------|----------------------------------------------------|----------------------------------------------------------------------|
| GET    | `/healthz`          | —                                                  | `{ status, service, syft_path, … }`                                 |
| GET    | `/readyz`           | —                                                  | `{ status }`                                                         |
| GET    | `/metrics`          | —                                                  | Prometheus text exposition                                           |
| POST   | `/sbom/generate`    | `{ source, format, scope, git_sha, sign }`         | `{ sbom_id, format, data, component_count, size_bytes, sha256, … }`  |
| POST   | `/sbom/analyze`     | `{ sbom_id }`                                      | `{ components, transitive_depth, ecosystems, license_breakdown, total_size_bytes }` |
| GET    | `/sbom/{id}`        | `?format=cyclonedx-json\|cyclonedx-xml\|spdx-json\|spdx-tag-value` | Stored SBOM body (CycloneDX JSON by default) |
| GET    | `/sbom`             | `?page=1&page_size=20`                             | `{ items, page, page_size, total }`                                  |
| DELETE | `/sbom/{id}`        | —                                                  | `{ deleted, sbom_id }`                                               |

### `POST /sbom/generate` — full payload

```json
{
  "source": "git:https://github.com/aionrs/aionrs-command-center.git",
  "format": "cyclonedx-json",
  "scope": "monorepo",
  "git_sha": "a1b2c3d",
  "sign": false
}
```

### `POST /sbom/analyze` — example

```json
{ "sbom_id": "sbom-2026-06-12-a1b2c3d-monorepo" }
```

Response:

```json
{
  "sbom_id": "sbom-2026-06-12-a1b2c3d-monorepo",
  "components": 247,
  "transitive_depth": 8,
  "ecosystems": ["npm", "pypi", "oci"],
  "license_breakdown": { "MIT": 112, "Apache-2.0": 67, "BSD-3-Clause": 41, "unknown": 27 },
  "total_size_bytes": 184927403,
  "analyzed_at": "2026-06-12T19:25:00.123Z"
}
```

## Source prefix matrix

| Prefix       | Maps to        | Example                                  |
|--------------|----------------|------------------------------------------|
| `docker:`    | container image| `docker:nginx:1.25`                      |
| `git:`       | git URL/path   | `git:https://github.com/aionrs/aionrs`   |
| `fs:`        | directory      | `fs:/var/lib/myapp`                      |
| `lockfile:`  | single file    | `lockfile:/path/to/package-lock.json`    |

## CLI

```bash
# Generate a CycloneDX JSON SBOM for an image
python -m sbom_pipeline generate --source "docker:nginx:1.25" \
    --format cyclonedx-json --save nginx.sbom.json

# Generate in offline mode (no live service required)
python -m sbom_pipeline generate --source "docker:alpine:3.18" --offline

# Analyze a stored SBOM
python -m sbom_pipeline analyze --sbom-id "sbom-2026-06-12-a1b2c3d-monorepo"

# List stored SBOMs
python -m sbom_pipeline list --page 1 --page-size 20

# Retrieve a stored SBOM as CycloneDX JSON
python -m sbom_pipeline get --sbom-id "sbom-2026-06-12-a1b2c3d-monorepo" \
    --format cyclonedx-json --output sbom.json

# Delete a stored SBOM
python -m sbom_pipeline delete --sbom-id "sbom-2026-06-12-a1b2c3d-monorepo"
```

## Event bus contract

The service emits on these subjects (Lead-locked + GitOpsManager
S2.10 contract):

| Subject                              | Direction | Payload                                                                                  |
|--------------------------------------|-----------|------------------------------------------------------------------------------------------|
| `security.sbom.requested.v1`         | inbound   | `{ source, format, scope, git_sha }`                                                     |
| `security.sbom.generated.v1`         | outbound  | `{ sbom_id, source, format, component_count, generated_at, git_sha, scope }`             |
| `security.sbom.failed.v1`            | outbound  | `{ source, error, failed_at, requested_by }`                                             |
| `security.sbom.analyzed.v1`          | outbound  | `{ sbom_id, transitive_depth, ecosystems, license_breakdown, total_size_bytes, analyzed_at }` |
| `security.sbom.stored.v1`            | outbound  | `{ sbom_id, sha256, size_bytes, stored_at }`                                             |

The auto-committer landed by GitOpsManager in S2.10 reads
`security.sbom.generated.v1` and persists files at
`security/sboms/<sbom_id>.<format>`.

## Configuration

All settings are env-driven (prefix `SBOM_`). See `.env.example` for
the full list. Highlights:

| Env var                       | Default                                            | Notes                                  |
|-------------------------------|----------------------------------------------------|----------------------------------------|
| `SBOM_PORT`                   | `4007`                                             |                                        |
| `SBOM_HOST`                   | `0.0.0.0`                                          |                                        |
| `SBOM_SYFT_BINARY`            | `syft`                                             | Absolute path or `$PATH` lookup        |
| `SBOM_REQUEST_TIMEOUT_SECONDS`| `600`                                              | Per-syft invocation timeout            |
| `SBOM_MAX_CONCURRENT_SCANS`   | `4`                                                | Global concurrency cap                 |
| `SBOM_DB_URL`                 | `sqlite+aiosqlite:///./backend/data/sbom.db`       | Use `postgresql+asyncpg://…` in prod   |
| `SBOM_OBJECT_STORE_URL`       | `fs://./backend/data/sbom-store`                   | Use `s3://bucket/prefix` in prod       |
| `SBOM_BUS_URL`                | `nats://localhost:4222`                            | Use `memory://` to disable the bus     |
| `SBOM_REQUIRE_AUTH`           | `false`                                            | When `true`, requires `Authorization: Bearer …` + `X-Tenant-Id` |

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       SBOM Pipeline service                        │
│                                                                    │
│   HTTP request ──► FastAPI (api.py) ──► generate() / analyze()     │
│                                            │                       │
│                                            ▼                       │
│                                       SyftRunner (syft_wrapper.py)│
│                                            │                       │
│                       ┌────────────────────┼──────────────────┐    │
│                       │                    ▼                  │    │
│   asyncio.subprocess  │             Syft CLI (binary)         │    │
│                       │                    │                  │    │
│                       │                    ▼                  │    │
│                       │             raw Syft JSON              │    │
│                       │                    │                  │    │
│                       │                    ▼                  │    │
│                       │         syft_to_cyclonedx()           │    │
│                       │                    │                  │    │
│                       │                    ▼                  │    │
│                       │              Sbom (internal)           │    │
│                       │                    │                  │    │
│                       │     ┌──────────────┼──────────────┐   │    │
│                       │     ▼              ▼              ▼   │    │
│                       │  CycloneDX-JSON CycloneDX-XML SPDX  │    │
│                       │     │              │              │   │    │
│                       │     └──────────────┼──────────────┘   │    │
│                       │                    ▼                  │    │
│                       │      SQLite metadata + S3/FS blob      │    │
│                       │                    │                  │    │
│                       │                    ▼                  │    │
│                       │     bus events: generated, failed,    │    │
│                       │                  analyzed, stored     │    │
│                       └────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Lint + format
ruff check src tests
ruff format src tests

# Type check
mypy src

# Tests
pytest
pytest --cov=src/sbom_pipeline --cov-report=term-missing

# Live integration tests (requires a real `syft` binary)
SBOM_RUN_LIVE_TESTS=1 pytest -m live
```

## File layout

```
sbom-pipeline-service/
├── README.md
├── pyproject.toml
├── Dockerfile
├── .env.example
├── .dockerignore
├── .gitignore
├── src/sbom_pipeline/
│   ├── __init__.py
│   ├── __main__.py
│   ├── main.py            (FastAPI app + lifespan)
│   ├── api.py             (route handlers)
│   ├── syft_wrapper.py    (Syft CLI subprocess wrapper)
│   ├── parsers.py         (CycloneDX + SPDX normalization)
│   ├── analyzer.py        (SBOM stats)
│   ├── store.py           (SQLite + object store)
│   ├── bus.py             (event publisher)
│   ├── telemetry.py       (OTel + Prometheus)
│   ├── config.py          (Pydantic-settings)
│   ├── errors.py          (typed exception hierarchy)
│   ├── models.py          (Pydantic v2)
│   └── cli.py             (Click)
└── tests/
    ├── conftest.py
    ├── test_syft_wrapper.py
    ├── test_parsers.py
    ├── test_analyzer.py
    ├── test_api.py
    └── fixtures/
        ├── sample-syft.json
        ├── sample-cyclonedx.json
        └── sample-spdx.spdx
```

## Handoff

- **S2.2 (Vuln Engine)** consumes SBOMs from the `security.sbom.
  generated.v1` bus event or the `GET /sbom/{id}` endpoint. The
  component list (`data.components[]`) is the round-trip shape.
- **S2.3 (Dependency Intelligence)** uses the analyzer's
  `transitive_depth` and the `dependencies[]` array of each SBOM
  to bootstrap the graph. The stable `bom-ref` format
  (`urn:cdx:<16 hex>`) is the join key.
- **S2.4 (Data Models)** is the wire-format source of truth
  (Zod schemas in `backend/models/security/sbom.model.ts`).
  This service mirrors those schemas field-for-field.
- **S2.5 (Security API)** calls `POST /sbom/generate`,
  `POST /sbom/analyze`, and `GET /sbom/{id}` from the Node
  security-service.
- **S2.6 (Dashboard UI)** renders the analyzer output and
  per-ecosystem breakdowns.
- **S2.9 (Compliance Auto-mapping)** uses the `license_breakdown`
  field for license risk scoring.
- **S2.10 (GitOps)** is already landed; the auto-committer reads
  `security.sbom.generated.v1`.

## License

Apache-2.0.
