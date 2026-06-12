"""Source adapters for vuln-intel."""
from .base import VulnerabilitySource
from .enrichment import EpssClient, KevClient
from .ghsa import GhsaSource, normalize_ghsa
from .nvd import NvdSource, normalize_nvd
from .osv import OsvSource, normalize_osv

__all__ = [
    "EpssClient",
    "GhsaSource",
    "KevClient",
    "NvdSource",
    "OsvSource",
    "VulnerabilitySource",
    "normalize_ghsa",
    "normalize_nvd",
    "normalize_osv",
]
