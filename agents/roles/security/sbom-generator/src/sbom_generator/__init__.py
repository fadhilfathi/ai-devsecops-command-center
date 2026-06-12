"""SBOM Generator — Syft-wrapped security agent.

A Python service that wraps the Anchore Syft CLI to produce software
bills-of-materials for arbitrary artifacts. Supports:

* Container images (Docker, OCI registries)
* Git repositories
* Local filesystems
* Language-specific lockfiles (npm, pip, Maven, Gradle, Go, Cargo, …)

Output is normalized to CycloneDX 1.5 JSON. A thin adapter layer can
serialize the same internal model to SPDX 2.3 tag-value or JSON for
cross-tool compatibility.
"""

from __future__ import annotations

from sbom_generator.models.request import GenerateRequest, SourceType
from sbom_generator.models.response import GenerateResponse, HealthResponse
from sbom_generator.models.sbom import (
    Component,
    ComponentType,
    SBOM,
    SBOMFormat,
    normalize_syft_output,
)
from sbom_generator.service import create_app

__all__ = [
    "Component",
    "ComponentType",
    "GenerateRequest",
    "GenerateResponse",
    "HealthResponse",
    "SBOM",
    "SBOMFormat",
    "SourceType",
    "create_app",
    "normalize_syft_output",
]

__version__ = "1.0.0"
