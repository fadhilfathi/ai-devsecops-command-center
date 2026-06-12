"""Base classes for vulnerability sources."""
from __future__ import annotations

import abc
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, Mapping

from ..models.cve import CveRecord
from ..validators import FeedValidator, ValidationResult, get_validator


class VulnerabilitySource(abc.ABC):
    """Abstract base for a vulnerability data source (NVD, GHSA, OSV, …)."""

    #: human-readable source name
    name: str

    @abc.abstractmethod
    async def fetch(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
        full: bool = False,
    ) -> AsyncIterator[CveRecord]:
        """Stream :class:`CveRecord` objects from the source."""
        raise NotImplementedError

    @abc.abstractmethod
    async def fetch_one(self, cve_id: str) -> CveRecord | None:
        """Fetch a single CVE by primary id (CVE-YYYY-NNNN).

        Implementations may also accept GHSA-…, PYSEC-…, etc.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def health(self) -> bool:
        """Lightweight probe used by the readiness check."""
        raise NotImplementedError

    # ---------------------------------------------------------------- S2.8
    #: Default no-op validator. Concrete sources override this to
    #: return a :class:`FeedValidator` bound to their schema. Returning
    #: ``None`` disables validation for that source.
    validator: FeedValidator | None = None

    def validate_raw(self, raw: Mapping[str, Any]) -> ValidationResult:
        """Validate a single raw upstream payload.

        Sources call this internally before parsing; the service
        layer also calls it to compute per-feed audit metrics. If the
        source does not have a validator wired (e.g. a custom
        implementation), this returns a passing result.
        """
        if self.validator is None:
            return ValidationResult(valid=True, record_id=None)
        return self.validator.validate_record(dict(raw))


def make_validator(source_name: str) -> FeedValidator | None:
    """Convenience constructor — returns ``None`` for unknown sources
    so callers can no-op cleanly."""
    try:
        return get_validator(source_name)
    except ValueError:
        return None
