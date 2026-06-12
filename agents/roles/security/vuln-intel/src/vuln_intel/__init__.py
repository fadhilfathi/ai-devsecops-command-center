"""vuln-intel — Vulnerability Intelligence Service (S2.2).

A Python service that ingests CVEs from NVD / GHSA / OSV, normalizes them
into a unified ``CveRecord`` schema, and attaches EPSS-based exploit
likelihood scores plus CISA KEV membership. The data is exposed over
HTTP for the security-service API (S2.5) and the dashboard UI (S2.6).

Quickstart::

    python -m vuln_intel

The service binds to ``0.0.0.0:${VULN_INTEL_PORT}`` (default 4008).
"""
from __future__ import annotations

__version__ = "0.1.0"
__service__ = "vuln-intel"

__all__ = ["__version__", "__service__"]
