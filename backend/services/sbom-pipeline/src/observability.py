# =============================================================================
# Per-service observability hook for sbom-pipeline (port 4007)
# Owner: SREEngineer
#
# This module wires the SBOM-pipeline-specific metrics and provides a
# thin `observe_scan` context manager for the scan flow. Importable as
# `from .observability import observe_scan, record_queue_depth`.
#
# Locked label set (PlatformArchitect S2.7 spec):
#   devsecops_sbom_generation_duration_seconds{source_type, ecosystem,
#                                              target_type, result}
#   - source_type : syft | dependency_track | import | manual
#   - ecosystem   : npm | pypi | maven | nuget | go | cargo | rubygems
#                 | composer | conan | apk | deb | rpm | generic
#   - target_type : image | filesystem | repo | archive | directory
#   - result      : success | failure | timeout | cancelled
# =============================================================================

from __future__ import annotations

import contextlib
import time
from typing import Iterator, Literal

from observability_py import (
    create_logger,
    active_scans,
    queue_depth,
    sbom_generation_duration_seconds,
    eventbus_lag_seconds,
    with_tenant,
)

SERVICE = "sbom-pipeline"
log = create_logger(service=SERVICE, version="0.1.0", env="dev", agent_id="syft-wrapper")


SourceType = Literal["syft", "dependency_track", "import", "manual"]
Ecosystem = Literal[
    "npm", "pypi", "maven", "nuget", "go", "cargo", "rubygems",
    "composer", "conan", "apk", "deb", "rpm", "generic",
]
TargetType = Literal["image", "filesystem", "repo", "archive", "directory"]
Result = Literal["success", "failure", "timeout", "cancelled"]


@contextlib.contextmanager
def observe_scan(
    tenant_id: str,
    source_type: SourceType,
    target_type: TargetType,
    target: str,
    ecosystem: Ecosystem = "generic",
) -> Iterator[dict]:
    """
    Context manager that:
      - Binds tenant_id into the logger
      - Increments active_scans{scanner_type="syft"}
      - Times the block and records devsecops_sbom_generation_duration_seconds
      - Emits structured start/end log lines

    Parameters
    ----------
    tenant_id    : Multi-tenant boundary tag (required).
    source_type  : Locked value (see module docstring).
    target_type  : Locked value (see module docstring).
    target       : The actual target (image:tag, repo URL, path). Logged only.
    ecosystem    : Locked value; defaults to "generic" for non-package-bearing
                   targets (e.g. a bare filesystem scan).

    Usage
    -----
        with observe_scan(tenant_id, "image", "image", target="nginx:1.25",
                          ecosystem="apk") as ctx:
            ... do the scan ...
            ctx["result"] = "success"   # optional override (defaults to "success")
    """
    bound_log = with_tenant(log, tenant_id)
    bound_log.info(
        "scan.begin",
        event="sbom.scan.begin",
        context={
            "source_type": source_type,
            "target_type": target_type,
            "ecosystem": ecosystem,
            "target": target,
        },
    )
    active_scans.labels(service=SERVICE, scanner_type="syft").inc()
    ctx: dict = {"result": "success"}
    started = time.monotonic()
    try:
        yield ctx
    except TimeoutError:
        ctx["result"] = "timeout"
        bound_log.error(
            "scan.timeout",
            event="sbom.scan.timeout",
            context={
                "source_type": source_type,
                "target_type": target_type,
                "ecosystem": ecosystem,
                "target": target,
            },
        )
        raise
    except Exception as exc:
        ctx["result"] = "failure"
        bound_log.error(
            "scan.fail",
            event="sbom.scan.fail",
            context={
                "source_type": source_type,
                "target_type": target_type,
                "ecosystem": ecosystem,
                "target": target,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            },
        )
        raise
    else:
        bound_log.info(
            "scan.ok",
            event="sbom.scan.ok",
            context={
                "source_type": source_type,
                "target_type": target_type,
                "ecosystem": ecosystem,
                "target": target,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )
    finally:
        elapsed = time.monotonic() - started
        sbom_generation_duration_seconds.labels(
            service=SERVICE,
            source_type=source_type,
            ecosystem=ecosystem,
            target_type=target_type,
            result=ctx["result"],
        ).observe(elapsed)
        active_scans.labels(service=SERVICE, scanner_type="syft").dec()


def record_queue_depth(depth: int) -> None:
    queue_depth.labels(service=SERVICE, queue_name="sbom_jobs").set(depth)


def record_eventbus_lag(stream: str, consumer_group: str, subject: str, lag_seconds: float) -> None:
    eventbus_lag_seconds.labels(
        service=SERVICE, stream=stream, consumer_group=consumer_group, subject=subject
    ).observe(lag_seconds)
