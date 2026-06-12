# SBOM Generator — Architecture

## Goals

1. Provide a single, well-typed entry point for producing SBOMs for
   every artifact the platform encounters.
2. Support **all four output formats** the platform promises
   (CycloneDX JSON, CycloneDX XML, SPDX JSON, SPDX tag-value) plus a
   native Syft JSON channel.
3. Stay decoupled from the rest of the system: the rest of the
   platform consumes SBOMs over HTTP or the event bus, not via
   in-process Python imports.
4. Be safe by default — input validation, bounded concurrency,
   per-request timeouts, structured error codes.
5. Be observable — every scan produces a span, a duration histogram,
   a counter increment, and a `sbom.generated` event.

## Why Syft?

Syft is the de-facto reference implementation for SBOM generation in
the CNCF / OpenSSF ecosystem. It supports more package ecosystems
than any other open-source scanner and exposes a stable JSON schema.
By wrapping the CLI as a subprocess we:

- Stay forward-compatible with upstream Syft releases (we just bump
  the pinned version in the Dockerfile).
- Avoid taking on Syft's transitive Go dependencies in our Python
  process.
- Get free parallelism from asyncio subprocesses.
- Can swap the backend later (e.g. for `cdxgen` or `trivy`) without
  changing the public API.

## Why FastAPI?

- Async-first — we can run multiple `syft` subprocesses concurrently
  on a single worker.
- First-class Pydantic integration for request/response validation.
- Auto-generated OpenAPI doc at `/docs` and `/openapi.json`.
- Production-grade server (uvicorn / gunicorn-uvicorn) with graceful
  shutdown.

## Internal data model

The :class:`SBOM` model is deliberately **agnostic of any external
SBOM spec**. Serializers are pure functions of the model. The
benefits:

- A bug in one serializer can't corrupt the model.
- Adding a new format (e.g. `in-toto`) only requires a new
  serializer.
- Tests can construct an `SBOM` directly without running Syft.

## Concurrency model

```
                  ┌──────────────────────────┐
HTTP request ───► │  FastAPI worker (1)      │
                  │                          │
                  │  ┌────────────────────┐  │
                  │  │ SBOMGeneratorAgent│  │
                  │  │  └─ SyftRunner    │  │ ──► asyncio.Semaphore(4)
                  │  └────────────────────┘  │           │
                  └──────────────────────────┘           ▼
                                              ┌──────────────────┐
                                              │  syft subprocess  │
                                              │  (1 per request)  │
                                              └──────────────────┘
```

The semaphore caps the number of concurrent Syft invocations. If a
second HTTP request arrives while all four slots are busy, it waits
in the queue. We do **not** spawn one process per request via
`--workers`; the default single-worker setup with a 4-slot semaphore
is enough for hundreds of small scans per minute and is much easier
to reason about for resource control.

## Failure modes

| Failure                             | Detection                  | Response                          |
|-------------------------------------|----------------------------|-----------------------------------|
| `syft` not on PATH                  | `resolve_syft` at boot     | 500 `syft_not_found`              |
| `syft` exit code != 0               | subprocess return code     | 502 `syft_execution_error`        |
| `syft` times out                    | `asyncio.wait_for`         | 504 `syft_timeout`                |
| Output exceeds 256 MiB              | byte length check          | 502 `syft_execution_error`        |
| Output is non-JSON                  | `json.JSONDecodeError`     | 502 `syft_execution_error`        |
| Bus publish fails                   | `RuntimeError` in publish  | logged; response still 200        |
| Unknown source type                 | pydantic validator         | 400 `validation_error`            |
| Auth header missing (when required) | service-level check        | 401 `unauthorized`                |

## Security considerations

- Runs as non-root (`aionrs:1001`) inside the container.
- The Syft binary is fetched from the official Anchore install
  script and pinned by version.
- The workspace directory is mounted as a tmpfs-friendly directory;
  no secrets should ever be written there.
- The service does not pull images from private registries itself —
  it expects registry credentials to be present in the environment
  for image scans (Syft will pick them up via standard
  `~/.docker/config.json` semantics).
- The `Authorization` header (when `REQUIRE_AUTH=true`) is checked
  by the service. Token verification is delegated to the platform's
  shared JWT verifier in a follow-up; the current implementation
  expects a bearer token to be present (the secret is validated at
  the ingress / sidecar level today).

## Observability

- **Logs** — structured JSON to stdout, one line per event.
- **Metrics** — Prometheus exposition at `/metrics`:
  - `sbom_jobs_total{format=…}`
  - `syft_duration_ms`
  - `components_per_scan`
  - `agent.start`, `agent.stop`, `bus_request.error`
- **Health** — `/healthz` reports syft version + path + bus state.
- **Readiness** — `/readyz` returns 503 until syft version probe
  succeeds.
- **Bus events** — `agent.ready` and `sbom.generated` are published
  with the canonical subject prefix.

## Extension points

| Need                                    | Where                                    |
|-----------------------------------------|------------------------------------------|
| New source kind                         | `models/request.py` + `syft.py:_syft_target` + `SUPPORTED_LOCKFILES` |
| New output format                       | `output.py` + `models/sbom.py:SBOMFormat`|
| Different event bus                     | `agent.py:BusClient` subclass             |
| Different scan engine (e.g. `cdxgen`)   | `syft.py:SyftRunner` (swap implementation)|
| Authentication provider                 | `service.py:_check_auth`                 |
| Per-tenant rate limiting                | `agent.py` (semaphore map by tenant)     |

## Sprint 2 acceptance criteria

| ID    | Criterion                                                     | Status |
|-------|---------------------------------------------------------------|--------|
| S2.1.1| Wraps Syft CLI as a subprocess                                | ✅     |
| S2.1.2| Supports Docker / OCI / Git / filesystems / archives          | ✅     |
| S2.1.3| Outputs CycloneDX 1.5 JSON and XML                            | ✅     |
| S2.1.4| Outputs SPDX 2.3 JSON and tag-value                           | ✅     |
| S2.1.5| Service runs on port 4007                                     | ✅     |
| S2.1.6| Bounded concurrency + per-request timeout                     | ✅     |
| S2.1.7| Health, readiness, metrics endpoints                          | ✅     |
| S2.1.8| Emits `sbom.generated` events on the bus                      | ✅     |
| S2.1.9| Unit tests for model, serializers, request validation, service | ✅     |
| S2.1.10| Containerized, runs as non-root                              | ✅     |
