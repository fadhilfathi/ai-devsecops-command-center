"""Correlation: pull vulnerabilities from vuln-intel (S2.2) and attach them
to graph nodes.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from .config import Settings
from .models.graph import DependencyGraph, NodeFinding

logger = logging.getLogger(__name__)


class VulnIntelClient:
    """Thin async client for the vuln-intel S2.2 service."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def _client_(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.vuln_intel_timeout_s,
                headers={"User-Agent": "ai-devsecops/dependency-intel/0.1"},
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health(self) -> bool:
        try:
            client = await self._client_()
            r = await client.get(self.settings.vuln_intel_url.rstrip("/") + "/livez")
            return r.status_code == 200
        except httpx.HTTPError as exc:  # noqa: BLE001
            logger.warning("vuln_intel_health_failed", error=str(exc))
            return False

    async def match_components(
        self,
        components: list[dict[str, Any]],
        *,
        min_severity: str = "UNKNOWN",
        exploited_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Call POST /vuln-intel/match on the upstream service.

        The request payload uses the same shape as the vuln-intel DTO.
        """
        client = await self._client_()
        url = self.settings.vuln_intel_url.rstrip("/") + "/vuln-intel/match"
        body = {
            "components": components,
            "min_severity": min_severity,
            "include_exploited_only": exploited_only,
        }
        r = await client.post(url, json=body)
        r.raise_for_status()
        data = r.json()
        return data.get("findings", []) or []

    async def get_stats(self) -> dict[str, Any]:
        client = await self._client_()
        url = self.settings.vuln_intel_url.rstrip("/") + "/vuln-intel/stats"
        r = await client.get(url)
        r.raise_for_status()
        return r.json()


def build_match_payload(graph: DependencyGraph) -> list[dict[str, Any]]:
    """Convert a :class:`DependencyGraph`'s nodes into the vuln-intel
    match payload shape.
    """
    out: list[dict[str, Any]] = []
    for node in graph.nodes.values():
        comp: dict[str, Any] = {"name": node.name, "ecosystem": node.ecosystem}
        if node.purl:
            comp["purl"] = node.purl
        if node.version:
            comp["version"] = node.version
        comp["package_manager"] = node.ecosystem
        out.append(comp)
    return out


def ingest_correlation(
    graph: DependencyGraph,
    findings: Iterable[dict[str, Any]],
) -> tuple[int, dict[str, int]]:
    """Attach upstream findings to the graph.

    Returns ``(attached_count, severity_distribution)``.
    """
    sev_dist: dict[str, int] = {}
    attached = 0
    # Build a fast lookup: lowercased purl / name -> node id
    purl_index: dict[str, str] = {n.purl.lower(): nid for nid, n in graph.nodes.items() if n.purl}
    name_index: dict[tuple[str, str], str] = {
        (n.name.lower(), (n.ecosystem or "").lower()): nid
        for nid, n in graph.nodes.items()
    }
    for f in findings:
        component = f.get("component", {}) or {}
        cve = f.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        node_id = _match_node(component, purl_index, name_index)
        if node_id is None:
            continue
        node = graph.nodes[node_id]
        severity = (cve.get("severity", {}) or {}).get("qualitative", "UNKNOWN")
        epss = None
        if cve.get("epss"):
            epss = float(cve["epss"]["score"])
        kev = bool(cve.get("kev") and cve["kev"].get("exploited"))
        finding = NodeFinding(
            cve_id=cve_id,
            severity=severity,
            epss=epss,
            kev=kev,
            confidence=float(f.get("confidence", 1.0)),
            matched_by=(
                "purl" if component.get("purl") else
                "ecosystem+name" if component.get("ecosystem") else
                "name"
            ),
            notes=(f.get("notes") or "")[:512] or None,
        )
        # Avoid duplicates
        if any(x.cve_id == cve_id for x in node.findings):
            continue
        node.findings.append(finding)
        sev_dist[severity] = sev_dist.get(severity, 0) + 1
        attached += 1
    return attached, sev_dist


def _match_node(
    component: dict[str, Any],
    purl_index: dict[str, str],
    name_index: dict[tuple[str, str], str],
) -> str | None:
    purl = component.get("purl")
    if purl:
        nid = purl_index.get(purl.lower())
        if nid:
            return nid
    name = (component.get("name") or "").lower()
    eco = (component.get("ecosystem") or "").lower()
    if name:
        nid = name_index.get((name, eco))
        if nid:
            return nid
        # fall back to name-only
        for (n, e), nid in name_index.items():
            if n == name:
                return nid
    return None
