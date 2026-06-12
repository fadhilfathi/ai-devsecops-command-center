# SBOM Generator — Integration & Operations Runbook

This document is the on-call reference for operating the SBOM
generator service in production.

## Container image

| Item          | Value                                              |
|---------------|----------------------------------------------------|
| Image         | `aionrs/sbom-generator`                            |
| Tag pattern   | `<git-sha>` for prod, `dev` for local              |
| Base          | `python:3.11-slim`                                 |
| Syft binary   | Anchore Syft, pinned via `SYFT_VERSION` build arg  |
| User          | `aionrs` (uid 1001)                                |
| Port          | `4007`                                             |
| Healthcheck   | `GET /healthz` every 30s                           |

## Resource requests / limits (recommended)

```yaml
requests:
  cpu: 200m
  memory: 512Mi
limits:
  cpu: 1
  memory: 2Gi
```

Syft itself is single-threaded and bounded by the artifact's layer
count. The Python process is small; memory spikes correlate with
`MAX_STDOUT_BYTES` (default 256 MiB).

## Scaling

- Vertical: increase `MAX_CONCURRENT_SCANS` to allow more parallel
  Syft processes (watch memory).
- Horizontal: run multiple replicas. The agent is stateless apart
  from the bus subscription queue (`sbom-generators`); the bus
  will load-balance requests across the group.
- For very large images (> 1 GB), use a dedicated pool of replicas
  with `MAX_CONCURRENT_SCANS=1` and `REQUEST_TIMEOUT_SECONDS=1800`.

## Known failure modes

### "syft not found"

The container failed to download Syft. Check egress to
`raw.githubusercontent.com` and `github.com` (Syft releases are
hosted on GitHub).

### "syft_execution_error" on a known-good image

Check `syft` exit code in the response details. Common causes:

- Image is private and the pod lacks registry credentials.
- Image manifest lists only foreign architectures (`linux/arm64`
  on an amd64 node).
- Syft version too old for the catalogers required (bump
  `SYFT_VERSION`).

### High p99 latency

- Inspect the `syft_duration_ms` histogram. If it's tail-heavy, the
  bottleneck is Syft itself (image pull / unpack). Consider
  pre-pulling images into a sidecar or using a registry mirror.
- If the histogram is uniform but the HTTP p99 is high, the
  semaphore queue is saturated — increase `MAX_CONCURRENT_SCANS` or
  add replicas.

## Runbook: rotating Syft

1. Bump `SYFT_VERSION` in `Dockerfile` and `scripts/build.sh`.
2. Build & push the new image.
3. Roll the deployment (`kubectl rollout restart deployment/sbom-generator`).
4. Watch `/metrics` for the `syft_version` gauge to update.
5. Tail logs for any new `deprecat` or `warn` lines.

## Runbook: changing the bus URL

1. Update the `BUS_URL` env var in the deployment manifest.
2. Restart the deployment.
3. Confirm `/healthz` reports `bus.connected: true`.

## SLIs / SLOs (recommended starting points)

| SLI                                              | SLO     |
|--------------------------------------------------|---------|
| `1 - (5xx / total)` (success rate)               | 99.5%   |
| `/v1/sbom/generate` p99 latency                  | < 30s   |
| `/healthz` uptime                                | 99.9%   |
