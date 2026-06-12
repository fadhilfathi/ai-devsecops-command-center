"""NVD 2.0 source adapter.

Reference: https://nvd.nist.gov/developers/v2
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
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
from .base import VulnerabilitySource, make_validator
from ..validators import get_validator as _get_item_validator

logger = logging.getLogger(__name__)


_PRIMARY_METRICS = ("CVSS:3.1", "CVSS:3.0", "CVSS:4.0", "CVSS:2.0")


def _parse_nvd_published(raw: str | None) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _select_cvss(metrics: dict[str, list[dict[str, Any]]]) -> tuple[CvssScore | None, CvssScore | None, CvssScore | None]:
    """Pick CVSS v3, v4, v2 from the NVD ``metrics`` block.

    NVD supplies up to 4 CVSS entries per CVE. The PRIMARY one is the
    authoritative; we use that whenever present. Otherwise we pick the
    first available.
    """
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None
    cvss_v2: CvssScore | None = None

    for cvss_key, container, builder in (
        ("cvssMetricV40", "cvssMetricV40", "v4"),
        ("cvssMetricV31", "cvssMetricV31", "v3"),
        ("cvssMetricV30", "cvssMetricV30", "v3"),
        ("cvssMetricV2", "cvssMetricV2", "v2"),
    ):
        if cvss_key not in metrics:
            continue
        for entry in metrics[cvss_key]:
            cvss_data = entry.get("cvssData", {})
            vector = cvss_data.get("vectorString")
            raw_score = cvss_data.get("baseScore")
            if not vector:
                continue
            # Prefer the PRIMARY source
            source = entry.get("type", "Secondary")
            score_source = ScoreSource.NVD_PRIMARY if source == "Primary" else ScoreSource.NVD_SECONDARY
            try:
                if cvss_key in ("cvssMetricV40",):
                    score = float(raw_score) if raw_score is not None else 0.0
                    cs = parse_cvss4_vector(vector, upstream_score=score)
                    cs_no_ref = CvssScore.model_construct(
                        version=cs.version,
                        vector=cs.vector,
                        score=cs.score,
                        severity=cvss4_severity_from_score(cs.score),
                        source=score_source,
                    )
                    cvss_v4 = cs_no_ref
                elif cvss_key in ("cvssMetricV31", "cvssMetricV30"):
                    cs = parse_cvss3_vector(vector)
                    cs_no_ref = CvssScore.model_construct(
                        version=cs.version,
                        vector=cs.vector,
                        score=cs.score,
                        severity=cvss3_severity_from_score(cs.score),
                        source=score_source,
                    )
                    cvss_v3 = cs_no_ref
                else:  # CVSS v2
                    # Compute a v3-style severity bucket from the v2 score
                    s = float(raw_score) if raw_score is not None else 0.0
                    sev = (
                        cvss3_severity_from_score(s * 2.5)  # rough v2->v3 mapping
                        if s > 0
                        else cvss3_severity_from_score(0.0)
                    )
                    cvss_v2 = CvssScore(
                        version="2.0",
                        vector=vector,
                        score=s,
                        severity=sev,
                        source=score_source,
                    )
            except (ValueError, KeyError, TypeError) as exc:
                logger.debug("NVD: failed to parse CVSS %s: %s", vector, exc)
                continue
            if entry.get("type") == "Primary":
                # Found the authoritative score — stop searching
                if builder == "v3" and cvss_v3:
                    return cvss_v3, cvss_v4, cvss_v2
                if builder == "v4" and cvss_v4:
                    return cvss_v3, cvss_v4, cvss_v2
                if builder == "v2" and cvss_v2:
                    return cvss_v3, cvss_v4, cvss_v2
    return cvss_v3, cvss_v4, cvss_v2


def _parse_nvd_description(descriptions: list[dict[str, str]] | None) -> str | None:
    if not descriptions:
        return None
    for d in descriptions:
        if d.get("lang") in (None, "en"):
            return d.get("value")
    return descriptions[0].get("value") if descriptions else None


def _cwe_ids_from_nvd(weaknesses: list[dict[str, Any]] | None) -> list[int]:
    out: list[int] = []
    if not weaknesses:
        return out
    for w in weaknesses:
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                try:
                    out.append(int(v.removeprefix("CWE-")))
                except ValueError:
                    pass
    return out


def _affected_packages_from_nvd(configurations: list[dict[str, Any]] | None) -> list[AffectedPackage]:
    """Best-effort extraction of affected packages from NVD configurations.

    NVD configurations are a deeply nested CPE tree. We flatten it to a
    list of ``AffectedPackage`` for display purposes; matching against
    SBOMs is done in the dependency-intel service using the PURL.
    """
    pkgs: list[AffectedPackage] = []
    if not configurations:
        return pkgs

    def _walk(node: dict[str, Any]) -> None:
        for cpe in node.get("cpeMatch", []) or []:
            if not cpe.get("vulnerable"):
                continue
            crit = cpe.get("criteria", "")
            # criteria looks like:
            # cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*
            parts = crit.split(":")
            if len(parts) >= 6 and parts[2] in ("a", "o", "h"):
                vendor = parts[3]
                product = parts[4]
                version = parts[5]
                if vendor in ("*",) and product in ("*",):
                    # Fall back to version-only
                    name = version if version not in ("*",) else crit
                elif product in ("*",):
                    name = vendor
                elif vendor in ("*",):
                    name = product
                else:
                    name = f"{vendor}:{product}"
                ap = AffectedPackage(
                    name=name,
                    ecosystem=parts[2],
                    package_manager=None,
                    versions=[
                        AffectedVersionRange(
                            introduced=cpe.get("versionStartIncluding"),
                            fixed=cpe.get("versionEndExcluding"),
                            last_affected=cpe.get("versionEndIncluding"),
                        )
                    ],
                )
                pkgs.append(ap)
        # NVD nests CPE matches inside a "nodes" list
        for child_node in node.get("nodes", []) or []:
            _walk(child_node)
        for child in node.get("children", []) or []:
            _walk(child)

    for cfg in configurations:
        # Configurations can either be a "cpeMatch" container or a "nodes" container
        _walk(cfg)
    return pkgs


def normalize_nvd(payload: dict[str, Any]) -> CveRecord | None:
    """Normalize a single NVD 2.0 vulnerability payload to a ``CveRecord``."""
    cve = payload.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    published = _parse_nvd_published(cve.get("published"))
    modified = _parse_nvd_published(cve.get("lastModified"))
    description = _parse_nvd_description(cve.get("descriptions"))
    cwes = _cwe_ids_from_nvd(cve.get("weaknesses"))
    refs = [
        Reference(url=r.get("url", ""), type=None, tags=r.get("tags", []))
        for r in (cve.get("references") or [])
        if r.get("url")
    ]
    cvss_v3, cvss_v4, cvss_v2 = _select_cvss(cve.get("metrics", {}))
    severity = aggregate_severity(
        cvss_v3=cvss_v3, cvss_v4=cvss_v4, cvss_v2=cvss_v2,
        primary_source=ScoreSource.NVD_PRIMARY,
    )

    affected = _affected_packages_from_nvd(cve.get("configurations"))

    return CveRecord(
        id=cve_id,
        aliases=[],
        source=[SourceName.NVD],
        published=published,
        modified=modified,
        summary=(description or "")[:280] or None,
        details=description,
        severity=severity,
        affected=affected,
        references=refs,
        cwes=cwes,
        raw={"nvd": payload},
    )


class NvdSource(VulnerabilitySource):
    name = SourceName.NVD

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client
        # S2.8: per-source JSON-Schema validator
        self.validator = make_validator("nvd")

    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": "ai-devsecops/vuln-intel/0.1 (security)"}
        if self.settings.nvd_api_key:
            h["apiKey"] = self.settings.nvd_api_key
        return h

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.nvd_request_timeout_s, headers=self._headers()
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
        start_index = 0
        results_per_page = 2000  # NVD max
        total: int | None = None
        emitted = 0
        while total is None or start_index < total:
            params: dict[str, Any] = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }
            if since and not full:
                # NVD requires the noRejected param to actually get records
                params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
                params["lastModEndDate"] = (datetime.now(timezone.utc)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000"
                )
            url = self.settings.nvd_base_url
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            total = int(data.get("totalResults", 0))
            for item in data.get("vulnerabilities", []) or []:
                # S2.8: per-record JSON-Schema validation
                if self.validator is not None:
                    vres = self.validator.validate_record(item)
                    if not vres.valid:
                        from ..telemetry import vuln_intel_validation_rejected_total
                        vuln_intel_validation_rejected_total.labels(
                            source="nvd", reason=vres.rejected_reason or "schema_violation"
                        ).inc()
                        logger.warning(
                            "validation_rejected source=nvd record_id=%s reason=%s",
                            vres.record_id, vres.rejected_reason,
                        )
                        continue
                rec = normalize_nvd(item)
                if rec is None:
                    continue
                yield rec
                emitted += 1
                if limit is not None and emitted >= limit:
                    return
            start_index += results_per_page
            if start_index >= total:
                break
            # be a polite API consumer — 6s between unauthenticated calls
            sleep_s = 0.6 if self.settings.nvd_api_key else 6.0
            await asyncio.sleep(sleep_s)

    async def fetch_one(self, cve_id: str) -> CveRecord | None:
        client = await self._client_()
        url = self.settings.nvd_base_url
        resp = await client.get(url, params={"cveId": cve_id})
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("vulnerabilities", []) or []:
            return normalize_nvd(item)
        return None

    async def health(self) -> bool:
        try:
            client = await self._client_()
            resp = await client.get(
                self.settings.nvd_base_url,
                params={"resultsPerPage": 1, "startIndex": 0},
            )
            return resp.status_code == 200
        except httpx.HTTPError as exc:  # noqa: BLE001
            logger.warning("NVD health probe failed: %s", exc)
            return False


def parse_nvd_lastmod_window(window: str) -> tuple[datetime, datetime]:
    """Helper used by tests — parse a 7-day sliding window."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    return start, end
