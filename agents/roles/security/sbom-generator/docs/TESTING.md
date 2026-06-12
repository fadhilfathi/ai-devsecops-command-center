# Test plan — SBOM Generator (S2.1)

This file describes the testing strategy for the SBOM generator
agent. It complements the executable tests in `tests/`.

## Layers

### 1. Unit tests (`tests/test_*.py`)

- **`test_sbom_model.py`** — internal model, fingerprint, normaliser.
- **`test_output.py`** — CycloneDX (JSON + XML) and SPDX (JSON +
  tag-value) serializers; round-trip parsing; media-type lookup.
- **`test_request_model.py`** — input validation for every source
  kind, format, scheme.
- **`test_service.py`** — FastAPI service using `TestClient` and
  fake runner / bus (no live Syft required).
- **`test_agent_and_syft.py`** — in-memory bus + Syft CLI argument
  builder.
- **`test_telemetry.py`** — counters, histograms, gauges, span
  context manager, Prometheus rendering.

All unit tests run in-process with no external dependencies and
complete in under 2s.

### 2. Live integration tests (`tests/test_integration_live.py`)

Gated by `SBOM_RUN_LIVE_TESTS=1` and a real `syft` binary on $PATH.
They verify:

- Syft version probe returns a real version string.
- Scanning a directory with a `package.json` finds `lodash`.
- CycloneDX mode emits `bomFormat: "CycloneDX"` and
  `specVersion: "1.5"`.

### 3. Container smoke tests (`.github/workflows/ci.yml`)

Run in CI on every PR:

- Build the image.
- `GET /healthz` returns `status: "ok"`.
- `POST /v1/sbom/quick` with `alpine:3.18` returns a non-empty
  CycloneDX SBOM.
- Self-scan: the service produces an SBOM for its own source code.

### 4. End-to-end validation (`S2.11`)

Owned by the Leader. Will run after S2.5 (security-service API
layer) is in place. Will exercise the full path:

```
Git repo / image
  → security-service POST /sbom/generate
    → sbom-generator POST /v1/sbom/generate
      → syft CLI
        → CycloneDX JSON
          → security-service persists
            → dashboard renders
```

## Coverage targets

| Module                      | Target |
|-----------------------------|--------|
| `models/sbom.py`            | 95%    |
| `models/request.py`         | 95%    |
| `output.py`                 | 95%    |
| `syft.py` (pure helpers)    | 90%    |
| `agent.py` (bus plumbing)   | 85%    |
| `service.py`                | 85%    |
| `telemetry.py`              | 90%    |

## What's not tested

- Real OCI registry auth (relies on platform env; the
  NetworkPolicy + Secrets model in `deploy/kubernetes.yaml` is the
  primary control).
- Real image scans in CI (rate-limited / flky in GH Actions);
  covered by the live test suite locally.
- Long-running scans exceeding the 600s timeout (covered by
  `SyftTimeoutError` mapping in the service tests).
