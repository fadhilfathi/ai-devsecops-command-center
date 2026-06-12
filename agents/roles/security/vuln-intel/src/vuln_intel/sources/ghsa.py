"""GitHub Security Advisory (GHSA) source adapter.

Reference: https://docs.github.com/en/rest/security-advisories/global-advisories
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


def _extract_cve_id(payload: dict[str, Any]) -> str | None:
    for ident in payload.get("identifiers", []) or []:
        if ident.get("type") == "CVE" and ident.get("value"):
            return ident["value"].upper()
    return None


def _aliases_from_identifiers(payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for ident in payload.get("identifiers", []) or []:
        v = ident.get("value")
        t = ident.get("type", "").upper()
        if v and t != "CVE" and v not in out:
            out.append(v)
    return out


def _references_from_ghsa(payload: dict[str, Any]) -> list[Reference]:
    refs: list[Reference] = []
    for r in payload.get("references", []) or []:
        url = r.get("url")
        if not url:
            continue
        refs.append(
            Reference(
                url=url,
                type=None,
                tags=[t for t in (r.get("type") or "").split()] or [],
            )
        )
    return refs


def _cvss_from_ghsa(payload: dict[str, Any]) -> tuple[CvssScore | None, CvssScore | None]:
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None
    for entry in payload.get("cvss", {}) or {}:
        if not isinstance(entry, dict):
            continue
        vector = entry.get("vector_string") or entry.get("vectorString")
        score = entry.get("score")
        version = entry.get("version", "")
        if not vector or not isinstance(score, (int, float)):
            continue
        try:
            if str(version).startswith("4."):
                cvss_v4 = CvssScore(
                    version="4.0",
                    vector=vector,
                    score=float(score),
                    severity=cvss4_severity_from_score(float(score)),
                    source=ScoreSource.GHSA,
                )
            elif str(version).startswith("3."):
                # prefer our own parser
                cs = parse_cvss3_vector(vector)
                cvss_v3 = CvssScore.model_construct(
                    version=cs.version,
                    vector=cs.vector,
                    score=float(score),
                    severity=cvss3_severity_from_score(float(score)),
                    source=ScoreSource.GHSA,
                )
        except (ValueError, TypeError) as exc:
            logger.debug("GHSA: CVSS parse failed %s: %s", vector, exc)
    return cvss_v3, cvss_v4


def _affected_from_ghsa(payload: dict[str, Any]) -> list[AffectedPackage]:
    out: list[AffectedPackage] = []
    for vuln in payload.get("vulnerabilities", []) or []:
        pkg = vuln.get("package", {}) or {}
        if not pkg:
            continue
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        if not name:
            continue
        vulnerable_ranges: list[AffectedVersionRange] = []
        # ``vulnerable_version_range`` is a *string* (e.g. ">= 1.0, < 1.2.4")
        vrange = vuln.get("vulnerable_version_range")
        if isinstance(vrange, str):
            # Best-effort parse: ">= X, < Y" or ">= X, <= Y"
            introduced = None
            fixed = None
            for token in vrange.split(","):
                token = token.strip()
                if token.startswith(">="):
                    introduced = token[2:].strip()
                elif token.startswith(">"):
                    introduced = token[1:].strip()
                elif token.startswith("<="):
                    fixed = token[2:].strip()
                elif token.startswith("<"):
                    fixed = token[1:].strip()
            if introduced or fixed:
                vulnerable_ranges.append(AffectedVersionRange(introduced=introduced, fixed=fixed))
        elif isinstance(vrange, list):
            for vr in vrange:
                vulnerable_ranges.append(
                    AffectedVersionRange(
                        introduced=vr.get("introduced"),
                        fixed=vr.get("fixed"),
                    )
                )
        out.append(
            AffectedPackage(
                purl=pkg.get("purl"),
                ecosystem=ecosystem,
                name=name,
                package_manager=ecosystem,
                versions=vulnerable_ranges,
                default_status="affected" if vrange else "unknown",
            )
        )
    return out


def _cwes_from_ghsa(payload: dict[str, Any]) -> list[int]:
    out: list[int] = []
    for cwe_id in payload.get("cwes", []) or []:
        if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
            try:
                out.append(int(cwe_id.removeprefix("CWE-")))
            except ValueError:
                pass
    return out


def normalize_ghsa(payload: dict[str, Any]) -> CveRecord | None:
    cve_id = _extract_cve_id(payload)
    ghsa_id = payload.get("ghsa_id")
    if not cve_id and ghsa_id:
        cve_id = ghsa_id
    if not cve_id:
        return None

    cvss_v3, cvss_v4 = _cvss_from_ghsa(payload)
    severity_str = (payload.get("severity") or "").upper() or None
    fallback_sev = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
        "INFO": "NONE",
    }.get(severity_str or "", "UNKNOWN")  # type: ignore[arg-type]

    from ..models.cve import SeverityQualitative

    severity = aggregate_severity(
        cvss_v3=cvss_v3,
        cvss_v4=cvss_v4,
        primary_source=ScoreSource.GHSA,
        fallback_qualitative=SeverityQualitative(fallback_sev) if fallback_sev else SeverityQualitative.UNKNOWN,
    )

    return CveRecord(
        id=cve_id,
        aliases=_aliases_from_identifiers(payload),
        source=[SourceName.GHSA],
        published=_iso(payload.get("published_at")),
        modified=_iso(payload.get("updated_at")),
        summary=payload.get("summary"),
        details=payload.get("description"),
        severity=severity,
        affected=_affected_from_ghsa(payload),
        references=_references_from_ghsa(payload),
        cwes=_cwes_from_ghsa(payload),
        raw={"ghsa": payload},
    )


class GhsaSource(VulnerabilitySource):
    name = SourceName.GHSA

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "User-Agent": "ai-devsecops/vuln-intel/0.1"}
        if self.settings.github_token:
            h["Authorization"] = f"Bearer {self.settings.github_token}"
        return h

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.ghsa_request_timeout_s, headers=self._headers()
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
        client = await self._client_()
        page = 1
        per_page = 100
        emitted = 0
        while True:
            params: dict[str, Any] = {"per_page": per_page, "page": page}
            if since and not full:
                params["updated"] = ">=" + since.strftime("%Y-%m-%dT%H:%M:%SZ")
            url = self.settings.ghsa_base_url
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            batch = resp.json() or []
            if not batch:
                break
            for item in batch:
                rec = normalize_ghsa(item)
                if rec is None:
                    continue
                yield rec
                emitted += 1
                if limit is not None and emitted >= limit:
                    return
            if len(batch) < per_page:
                break
            page += 1
            # GHSA has a 5000 req/h limit when authenticated
            await asyncio.sleep(0.05 if self.settings.github_token else 1.0)

    async def fetch_one(self, cve_id: str) -> CveRecord | None:
        client = await self._client_()
        url = self.settings.ghsa_base_url
        # Accept either a CVE-… id (lookup via identifier) or a GHSA-… id
        if cve_id.startswith("GHSA-"):
            url = f"{url}/{cve_id}"
        else:
            url = f"{url}?cve_id={cve_id}"
        resp = await client.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            for entry in data:
                return normalize_ghsa(entry)
            return None
        return normalize_ghsa(data)

    async def health(self) -> bool:
        try:
            client = await self._client_()
            resp = await client.get(
                self.settings.ghsa_base_url, params={"per_page": 1}
            )
            return resp.status_code == 200
        except httpx.HTTPError as exc:  # noqa: BLE001
            logger.warning("GHSA health probe failed: %s", exc)
            return False
