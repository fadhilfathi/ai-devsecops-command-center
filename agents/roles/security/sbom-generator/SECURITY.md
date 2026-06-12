# Security Considerations — SBOM Generator

This file is a living document. Update it as new threats or
mitigations are identified.

## Threat model summary

| Threat                                | Mitigation                                              |
|---------------------------------------|---------------------------------------------------------|
| Malicious source path / image         | Input validation in `models/request.py`; `resolve_syft` |
| Syft binary tampering                 | Pinned `SYFT_VERSION`; image built from official script |
| Output flooding (zip bomb)            | `_MAX_STDOUT_BYTES = 256 MiB` cap in `syft.py`          |
| Bus message injection                 | JSON-only subjects, payload validated by pydantic       |
| Auth bypass                           | Bearer-token check + tenant header when `REQUIRE_AUTH`  |
| Privilege escalation in container     | Non-root user `aionrs:1001`; read-only root FS          |
| Resource exhaustion                   | `asyncio.Semaphore(MAX_CONCURRENT_SCANS)` + timeouts    |
| Tenant isolation                      | Tenant header plumbed into SBOM metadata only           |

## Inputs we accept

- HTTP request bodies (JSON) — validated by Pydantic.
- Bus payloads — JSON only, validated by Pydantic when the agent
  re-hydrates them.
- Syft subprocess stdout — capped at 256 MiB, must parse as JSON.
- Syft subprocess stderr — only used for warning extraction, never
  surfaced to callers verbatim.

## Outputs we produce

- HTTP responses — bounded to configured `formats`.
- Bus events — small JSON envelopes (`request_id`, counters).
- Prometheus metrics — labelled with source kind + format only.
- Log lines — structured JSON, never includes raw scan output.

## Things explicitly out of scope

- Verifying the SBOM's signature (CycloneDX / SPDX support
  detached signatures, but the platform handles signing at a
  higher layer).
- Storing SBOMs — the security-service owns persistence.
- Comparing SBOMs across runs — the dependency-intelligence layer
  (S2.3) consumes the SBOM and does the diff.
