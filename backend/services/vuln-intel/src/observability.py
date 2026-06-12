# =============================================================================
# Per-service observability hook for vuln-intel (port 4008)
# Owner: SREEngineer
# =============================================================================

from __future__ import annotations

import time
from typing import Iterable

from observability_py import (
    create_logger,
    queue_depth,
    vulnerability_ingestion_total,
    eventbus_lag_seconds,
    with_tenant,
)

SERVICE = "vuln-intel"
log = create_logger(service=SERVICE, version="0.1.0", env="dev", agent_id="vuln-intel-agent")


SEVERITY_BUCKETS = frozenset({"critical", "high", "medium", "low", "unknown"})
SOURCE_BUCKETS = frozenset({"nvd", "ghsa", "osv"})


def record_ingestion_batch(tenant_id: str, source: str, items: Iterable[dict]) -> int:
    """
    Increment vulnerability_ingestion_total for each (source, severity) pair.
    `items` is an iterable of dicts with at least a "severity" key.
    Returns the number of items recorded.
    """
    if source not in SOURCE_BUCKETS:
        # Defensive: any unknown source is folded into "unknown" to preserve cardinality.
        source = "unknown"
    bound_log = with_tenant(log, tenant_id)
    n = 0
    for it in items:
        sev = (it.get("severity") or "unknown").lower()
        if sev not in SEVERITY_BUCKETS:
            sev = "unknown"
        vulnerability_ingestion_total.labels(
            service=SERVICE, source=source, severity=sev
        ).inc()
        n += 1
    bound_log.info(
        "ingest.batch",
        event="vuln.ingest.batch",
        context={"source": source, "count": n},
    )
    return n


def record_queue_depth(depth: int) -> None:
    queue_depth.labels(service=SERVICE, queue_name="cve_processing").set(depth)


def record_eventbus_lag(stream: str, consumer_group: str, subject: str, lag_seconds: float) -> None:
    eventbus_lag_seconds.labels(
        service=SERVICE, stream=stream, consumer_group=consumer_group, subject=subject
    ).observe(lag_seconds)


def record_feed_freshness(source: str, age_seconds: float) -> None:
    """Convenience: log + emit a metric-as-event when a feed is refreshed."""
    log.info(
        "feed.refreshed",
        event="vuln.feed.refreshed",
        context={"source": source, "age_seconds": age_seconds},
    )
