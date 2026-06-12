# =============================================================================
# Per-service observability hook for dependency-intel (port 4009)
# Owner: SREEngineer
#
# Locked label set (PlatformArchitect S2.7 spec):
#   devsecops_risk_calculation_duration_seconds{sbom_size_bucket, algorithm,
#                                              result}
#   - sbom_size_bucket : small | medium | large | xlarge | xxlarge
#   - algorithm        : cvss_only | cvss_epss | cvss_epss_kev | full
#   - result           : success | failure | timeout | cancelled
# =============================================================================

from __future__ import annotations

import time
from typing import Iterator, Literal
import contextlib

from observability_py import (
    create_logger,
    queue_depth,
    risk_calculation_duration_seconds,
    sbom_size_bucket,
    eventbus_lag_seconds,
    with_tenant,
)

SERVICE = "dependency-intel"
log = create_logger(service=SERVICE, version="0.1.0", env="dev", agent_id="risk-calc-agent")


Algorithm = Literal["cvss_only", "cvss_epss", "cvss_epss_kev", "full"]
Result = Literal["success", "failure", "timeout", "cancelled"]


@contextlib.contextmanager
def observe_risk_calc(
    tenant_id: str,
    component_count: int,
    algorithm: Algorithm = "cvss_epss",
) -> Iterator[dict]:
    """
    Context manager that times a risk-calculation job and emits:
      - devsecops_risk_calculation_duration_seconds{sbom_size_bucket, algorithm,
                                                     result}
      - structured start/ok/fail log lines

    Parameters
    ----------
    tenant_id       : Multi-tenant boundary tag (required).
    component_count : Total components in the SBOM; the helper
                      sbom_size_bucket() picks the bucket automatically.
    algorithm       : Locked value (see module docstring). Defaults to
                      "cvss_epss" (the most common production algorithm).

    Usage
    -----
        with observe_risk_calc(tenant_id, 1234, "full") as ctx:
            ... do the calculation ...
    """
    bucket = sbom_size_bucket(component_count)
    bound_log = with_tenant(log, tenant_id)
    bound_log.info(
        "risk_calc.begin",
        event="risk.calc.begin",
        context={
            "sbom_size_bucket": bucket,
            "algorithm": algorithm,
            "component_count": component_count,
        },
    )
    started = time.monotonic()
    ctx: dict = {"result": "success"}
    try:
        yield ctx
    except TimeoutError:
        ctx["result"] = "timeout"
        bound_log.error(
            "risk_calc.timeout",
            event="risk.calc.timeout",
            context={"sbom_size_bucket": bucket, "algorithm": algorithm},
        )
        raise
    except Exception as exc:
        ctx["result"] = "failure"
        bound_log.error(
            "risk_calc.fail",
            event="risk.calc.fail",
            context={
                "sbom_size_bucket": bucket,
                "algorithm": algorithm,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            },
        )
        raise
    else:
        bound_log.info(
            "risk_calc.ok",
            event="risk.calc.ok",
            context={
                "sbom_size_bucket": bucket,
                "algorithm": algorithm,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )
    finally:
        risk_calculation_duration_seconds.labels(
            service=SERVICE,
            sbom_size_bucket=bucket,
            algorithm=algorithm,
            result=ctx["result"],
        ).observe(time.monotonic() - started)


def record_queue_depth(depth: int) -> None:
    queue_depth.labels(service=SERVICE, queue_name="risk_calc_jobs").set(depth)


def record_eventbus_lag(stream: str, consumer_group: str, subject: str, lag_seconds: float) -> None:
    eventbus_lag_seconds.labels(
        service=SERVICE, stream=stream, consumer_group=consumer_group, subject=subject
    ).observe(lag_seconds)
