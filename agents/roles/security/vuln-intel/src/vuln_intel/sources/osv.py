"""OSV.dev source adapter.

Reference: https://google.github.io/osv.dev/post-v1-api/
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx

from ..config import Settings
from ..models.cve import (
    AffectedPackage,
    AffectedVersionRange,
    CveRecord,
    CvssScore,
    Reference,
    ScoreSource,
    SourceName,
)
from ..scoring import (
    aggregate_severity,
    cvss3_severity_from_score,
    cvss4_severity_from_score,
    parse_cvss3_vector,
    parse_cvss4_vector,
)
from .base import VulnerabilitySource

logger = logging.getLogger(__name__)


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _osv_id(payload: dict[str, Any]) -> str | None:
    return payload.get("id")


def _aliases_from_osv(payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for a in payload.get("aliases", []) or []:
        if a and a != payload.get("id") and a not in out:
            out.append(a)
    for r in payload.get("related", []) or []:
        if r and r not in out:
            out.append(r)
    return out


def _references_from_osv(payload: dict[str, Any]) -> list[Reference]:
    refs: list[Reference] = []
    for r in payload.get("references", []) or []:
        url = r.get("url")
        if not url:
            continue
        refs.append(
            Reference(
                url=url,
                type=r.get("type"),
                tags=[t for t in (r.get("type") or "").split()] or [],
            )
        )
    return refs


def _cvss_from_osv(payload: dict[str, Any]) -> tuple[CvssScore | None, CvssScore | None]:
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None
    for entry in payload.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        vector = entry.get("vector")
        score = entry.get("score")
        t = (entry.get("type") or "").upper()
        if not vector or not isinstance(score, (int, float)):
            continue
        # OSV stores scores as "CVSS_V3" etc, in strings or floats
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            continue
        try:
            if t.startswith("CVSS:4") or t == "CVSS_V4":
                cs = parse_cvss4_vector(vector, upstream_score=score_f)
                cvss_v4 = CvssScore.model_construct(
                    version=cs.version,
                    vector=cs.vector,
                    score=score_f,
                    severity=cvss4_severity_from_score(score_f),
                    source=ScoreSource.OSV,
                )
            elif t.startswith("CVSS:3") or t == "CVSS_V3":
                # derive the precise score from the vector when possible
                try:
                    derived = parse_cvss3_vector(vector)
                    cvss_v3 = CvssScore.model_construct(
                        version=derived.version,
                        vector=vector,
                        score=derived.score,
                        severity=derived.severity,
                        source=ScoreSource.OSV,
                    )
                except ValueError:
                    cvss_v3 = CvssScore(
                        version="3.1",
                        vector=vector,
                        score=score_f,
                        severity=cvss3_severity_from_score(score_f),
                        source=ScoreSource.OSV,
                    )
        except (ValueError, TypeError) as exc:
            logger.debug("OSV: CVSS parse failed %s: %s", vector, exc)
    return cvss_v3, cvss_v4


def _affected_from_osv(payload: dict[str, Any]) -> list[AffectedPackage]:
    out: list[AffectedPackage] = []
    for aff in payload.get("affected", []) or []:
        purl = aff.get("package", {}).get("purl") if isinstance(aff.get("package"), dict) else None
        eco = aff.get("package", {}).get("ecosystem") if isinstance(aff.get("package"), dict) else None
        name = aff.get("package", {}).get("name") if isinstance(aff.get("package"), dict) else None
        if not name:
            continue
        versions: list[AffectedVersionRange] = []
        for r in aff.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                versions.append(
                    AffectedVersionRange(
                        introduced=ev.get("introduced"),
                        fixed=ev.get("fixed"),
                        last_affected=ev.get("last_affected"),
                    )
                )
        default_status = aff.get("database_specific", {}).get("last_known_affected_version_range", "")
        if default_status:
            default_status = "affected"
        out.append(
            AffectedPackage(
                purl=purl,
                ecosystem=eco,
                name=name,
                package_manager=eco,
                versions=versions,
                default_status=default_status or "unknown",  # type: ignore[arg-type]
            )
        )
    return out


def _cwes_from_osv(payload: dict[str, Any]) -> list[int]:
    out: list[int] = []
    db = payload.get("database_specific", {}) or {}
    for cwe in db.get("cwe_ids", []) or []:
        if isinstance(cwe, str) and cwe.startswith("CWE-"):
            try:
                out.append(int(cwe.removeprefix("CWE-")))
            except ValueError:
                pass
    return out


def normalize_osv(payload: dict[str, Any]) -> CveRecord | None:
    osv_id = _osv_id(payload)
    if not osv_id:
        return None
    # Promote CVE-… to primary id
    primary = osv_id
    for a in payload.get("aliases", []) or []:
        if a.startswith("CVE-"):
            primary = a
            break
    cvss_v3, cvss_v4 = _cvss_from_osv(payload)
    severity = aggregate_severity(
        cvss_v3=cvss_v3,
        cvss_v4=cvss_v4,
        primary_source=ScoreSource.OSV,
    )
    return CveRecord(
        id=primary,
        aliases=_aliases_from_osv(payload),
        source=[SourceName.OSV],
        published=_iso(payload.get("published")),
        modified=_iso(payload.get("modified")),
        summary=payload.get("summary"),
        details=payload.get("details"),
        severity=severity,
        affected=_affected_from_osv(payload),
        references=_references_from_osv(payload),
        cwes=_cwes_from_osv(payload),
        related=payload.get("related", []) or [],
        raw={"osv": payload},
    )


class OsvSource(VulnerabilitySource):
    name = SourceName.OSV

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.osv_request_timeout_s,
                headers={"User-Agent": "ai-devsecops/vuln-intel/0.1"},
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
        full: bool = False,
    ) -> AsyncIterator[CveRecord]:
        """Stream OSV records using the ``modified`` cursor.

        OSV's listing endpoints are limited; the canonical approach is to
        use the per-ecosystem exports, but the JSON API supports
        listing-all via a POST. For a sync, we instead use the
        per-ecosystem zip exports (e.g. https://osv-vulnerabilities.storage.googleapis.com/...zip)
        — but for a live service we use the `POST /v1/querybatch` API.
        """
        client = await self._client_()
        url = self.settings.osv_base_url + "/query"
        # OSV doesn't provide a true streaming endpoint. We paginate by
        # last-modified.
        batch_size = 1000
        modified_after: str | None = (
            since.strftime("%Y-%m-%dT%H:%M:%S") if since else None
        )
        emitted = 0
        while True:
            req_body: dict[str, Any] = {"page_token": "", "size": batch_size}
            if modified_after and not full:
                req_body["modified_since"] = modified_after
            resp = await client.post(url, json=req_body)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulns", []) or []
            for v in vulns:
                rec = normalize_osv(v)
                if rec is None:
                    continue
                yield rec
                emitted += 1
                if limit is not None and emitted >= limit:
                    return
            next_token = data.get("next_page_token")
            if not next_token:
                break
            # OSV allows continuous page_token queries
            url = self.settings.osv_base_url + "/query"  # POST stays the same
            modified_after = None  # token carries the cursor
            await asyncio.sleep(0.1)

    async def fetch_one(self, cve_id: str) -> CveRecord | None:
        client = await self._client_()
        url = f"{self.settings.osv_base_url}/vulns/{cve_id}"
        resp = await client.get(url)
        if resp.status_code == 404:
            # Try alias lookup via POST /v1/query
            query = await client.post(
                f"{self.settings.osv_base_url}/query",
                json={"query": {"alias": cve_id}},
            )
            if query.status_code == 200:
                data = query.json()
                for v in data.get("vulns", []) or []:
                    return normalize_osv(v)
            return None
        resp.raise_for_status()
        return normalize_osv(resp.json())

    async def health(self) -> bool:
        try:
            client = await self._client_()
            resp = await client.post(
                f"{self.settings.osv_base_url}/query", json={"size": 1}
            )
            return resp.status_code == 200
        except httpx.HTTPError as exc:  # noqa: BLE001
            logger.warning("OSV health probe failed: %s", exc)
            return False
