"""Tests for source normalizers (NVD, GHSA, OSV)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_intel.sources.ghsa import normalize_ghsa
from vuln_intel.sources.nvd import normalize_nvd
from vuln_intel.sources.osv import normalize_osv


# -----------------------------------------------------------------------------
# NVD
# -----------------------------------------------------------------------------


NVD_FIXTURE = {
    "cve": {
        "id": "CVE-2024-31337",
        "published": "2024-04-30T16:15:00.000",
        "lastModified": "2024-05-01T17:31:00.000",
        "descriptions": [
            {"lang": "en", "value": "Path traversal in the example package."},
            {"lang": "es", "value": "Recorrido de ruta en el paquete de ejemplo."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-22"}]},
        ],
        "references": [
            {"url": "https://example.com/cve-2024-31337"},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:foo:1.0:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "1.2.4",
                            }
                        ]
                    }
                ]
            }
        ],
    }
}


def test_normalize_nvd_basic() -> None:
    rec = normalize_nvd(NVD_FIXTURE)
    assert rec is not None
    assert rec.id == "CVE-2024-31337"
    assert rec.severity.qualitative.value == "CRITICAL"
    assert rec.severity.cvss_v3 is not None
    assert rec.severity.cvss_v3.score == 9.8
    assert rec.cwes == [22]
    assert rec.published is not None
    assert rec.published.year == 2024
    assert rec.affected[0].name == "example:foo"
    assert rec.affected[0].versions[0].introduced == "1.0"


def test_normalize_nvd_missing_id() -> None:
    payload = {"cve": {"id": ""}}
    assert normalize_nvd(payload) is None


# -----------------------------------------------------------------------------
# GHSA
# -----------------------------------------------------------------------------


GHSA_FIXTURE = {
    "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
    "cve_id": None,
    "identifiers": [
        {"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
        {"type": "CVE", "value": "CVE-2024-31337"},
    ],
    "summary": "Path traversal in example/foo",
    "description": "Long description…",
    "severity": "high",
    "published_at": "2024-04-30T16:15:00Z",
    "updated_at": "2024-05-01T17:31:00Z",
    "cvss": {
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
    },
    "cwes": ["CWE-22"],
    "references": [{"url": "https://example.com/ghsa"}],
    "vulnerabilities": [
        {
            "package": {
                "ecosystem": "npm",
                "name": "foo",
                "purl": "pkg:npm/foo@1.0.0",
            },
            "vulnerable_version_range": ">= 1.0, < 1.2.4",
        }
    ],
}


def test_normalize_ghsa_basic() -> None:
    rec = normalize_ghsa(GHSA_FIXTURE)
    assert rec is not None
    assert rec.id == "CVE-2024-31337"
    assert "GHSA-xxxx-yyyy-zzzz" in rec.aliases
    assert rec.severity.qualitative.value in {"HIGH", "CRITICAL"}  # high string + 9.8 -> CRITICAL
    assert rec.affected[0].name == "foo"
    assert rec.affected[0].ecosystem == "npm"
    assert rec.affected[0].purl == "pkg:npm/foo@1.0.0"


# -----------------------------------------------------------------------------
# OSV
# -----------------------------------------------------------------------------


OSV_FIXTURE = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2024-31337", "PYSEC-2024-50"],
    "summary": "Path traversal in foo",
    "details": "Long description…",
    "published": "2024-04-30T16:15:00Z",
    "modified": "2024-05-01T17:31:00Z",
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ],
    "affected": [
        {
            "package": {
                "ecosystem": "PyPI",
                "name": "foo",
                "purl": "pkg:pypi/foo@1.0.0",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.2.4"},
                    ],
                }
            ],
        }
    ],
    "references": [{"type": "WEB", "url": "https://example.com/osv"}],
    "database_specific": {"cwe_ids": ["CWE-22"]},
}


def test_normalize_osv_basic() -> None:
    rec = normalize_osv(OSV_FIXTURE)
    assert rec is not None
    assert rec.id == "CVE-2024-31337"  # promoted from alias
    assert "GHSA-aaaa-bbbb-cccc" in rec.aliases
    assert rec.severity.qualitative.value == "CRITICAL"
    assert rec.affected[0].purl == "pkg:pypi/foo@1.0.0"
    assert rec.affected[0].versions[0].introduced == "0"
    assert rec.affected[0].versions[0].fixed == "1.2.4"


def test_normalize_osv_promotes_cve_alias() -> None:
    rec = normalize_osv(OSV_FIXTURE)
    assert rec is not None
    assert rec.id == "CVE-2024-31337"


def test_load_nvd_fixture_file() -> None:
    """Sanity check that a real-world-style payload round-trips."""
    # Build a minimal payload using the in-test fixture
    p = Path("/tmp/nvd-fixture.json")  # noqa: S108
    p.write_text(json.dumps(NVD_FIXTURE))
    data = json.loads(p.read_text())
    rec = normalize_nvd(data)
    assert rec is not None
    assert rec.id == "CVE-2024-31337"
