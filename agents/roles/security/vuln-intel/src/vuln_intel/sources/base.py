"""Base classes for vulnerability sources."""
from __future__ import annotations

import abc
from collections.abc import AsyncIterator
from datetime import datetime

from ..models.cve import CveRecord


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
