"""EPSS (FIRST.org) + CISA KEV adapters.

These two data sources do not produce new ``CveRecord`` objects — they
*enrich* existing ones with exploit likelihood (EPSS) and Known
Exploited Vulnerability status (KEV).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from ..config import Settings
from ..models.cve import EpssScore, KevEntry

logger = logging.getLogger(__name__)


class EpssClient:
    """Client for the FIRST.org EPSS API.

    Spec: https://api.first.org/data/v1/epss
    """

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.epss_request_timeout_s,
                headers={"User-Agent": "ai-devsecops/vuln-intel/0.1"},
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """Fetch EPSS for a list of CVE ids.

        The API limits query length; we chunk to 100 ids per request and
        return a dict keyed by upper-cased CVE id.
        """
        if not cve_ids:
            return {}
        client = await self._client_()
        result: dict[str, EpssScore] = {}
        chunk = 100
        for i in range(0, len(cve_ids), chunk):
            ids = ",".join(c.upper() for c in cve_ids[i : i + chunk])
            url = f"{self.settings.epss_base_url}?cve={ids}"
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            for row in data.get("data", []) or []:
                cve = (row.get("cve") or "").upper()
                if not cve:
                    continue
                try:
                    result[cve] = EpssScore(
                        score=float(row["epss"]),
                        percentile=float(row["percentile"]),
                        fetched_at=datetime.utcnow(),
                    )
                except (KeyError, ValueError, TypeError) as exc:
                    logger.debug("EPSS: bad row %s: %s", row, exc)
        return result

    async def health(self) -> bool:
        try:
            client = await self._client_()
            resp = await client.get(self.settings.epss_base_url)
            return resp.status_code == 200
        except httpx.HTTPError as exc:  # noqa: BLE001
            logger.warning("EPSS health probe failed: %s", exc)
            return False


class KevClient:
    """Client for the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client
        self._cache: dict[str, KevEntry] = {}

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.kev_request_timeout_s,
                headers={"User-Agent": "ai-devsecops/vuln-intel/0.1"},
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def refresh(self) -> dict[str, KevEntry]:
        client = await self._client_()
        resp = await client.get(self.settings.kev_base_url)
        resp.raise_for_status()
        data = resp.json()
        out: dict[str, KevEntry] = {}
        for entry in data.get("vulnerabilities", []) or []:
            cve = (entry.get("cveID") or "").upper()
            if not cve:
                continue
            out[cve] = KevEntry(
                exploited=True,
                date_added=_iso(entry.get("dateAdded")),
                due_date=_iso(entry.get("dueDate")),
                ransomware_use=(
                    (entry.get("knownRansomwareCampaignUse") or "").lower() == "known"
                    if entry.get("knownRansomwareCampaignUse") is not None
                    else None
                ),
                notes=entry.get("shortDescription") or entry.get("vulnerabilityName"),
            )
        self._cache = out
        return out

    async def lookup(self, cve_id: str) -> KevEntry | None:
        if not self._cache:
            await self.refresh()
        return self._cache.get(cve_id.upper())

    async def health(self) -> bool:
        try:
            client = await self._client_()
            resp = await client.get(self.settings.kev_base_url, timeout=5.0)
            return resp.status_code == 200
        except httpx.HTTPError as exc:  # noqa: BLE001
            logger.warning("KEV health probe failed: %s", exc)
            return False


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
