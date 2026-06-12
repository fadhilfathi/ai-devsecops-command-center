"""Runtime configuration for the SBOM generator service.

The settings object is populated from environment variables and the
command-line. The values are read once at boot, frozen, and passed
explicitly through dependency injection to the rest of the service so
that tests can override any value without monkey-patching modules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Settings:
    """Immutable application settings."""

    syft_binary: str = "syft"
    syft_config: Optional[Path] = None
    bus_url: str = "nats://localhost:4222"
    bus_subject_prefix: str = "aionrs.security.sbom"
    host: str = "0.0.0.0"
    port: int = 4007
    workspace_root: Path = field(
        default_factory=lambda: Path(
            os.environ.get("SBOM_WORKSPACE", "/var/lib/aionrs/sbom-workspace")
        )
    )
    request_timeout_seconds: int = 600
    max_concurrent_scans: int = 4
    default_format: str = "cyclonedx-json"
    user_agent: str = "aionrs-sbom-generator/1.0.0"
    service_name: str = "sbom-generator"
    tenant_header: str = "x-tenant-id"
    auth_header: str = "authorization"
    require_auth: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        """Build a Settings instance from environment variables."""
        workspace = os.environ.get("SBOM_WORKSPACE")
        return cls(
            syft_binary=os.environ.get("SYFT_BINARY", "syft"),
            bus_url=os.environ.get("BUS_URL", "nats://localhost:4222"),
            bus_subject_prefix=os.environ.get(
                "BUS_SUBJECT_PREFIX", "aionrs.security.sbom"
            ),
            host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "4007")),
            workspace_root=Path(workspace) if workspace else cls.workspace_root,
            request_timeout_seconds=int(
                os.environ.get("REQUEST_TIMEOUT_SECONDS", "600")
            ),
            max_concurrent_scans=int(os.environ.get("MAX_CONCURRENT_SCANS", "4")),
            default_format=os.environ.get("DEFAULT_FORMAT", "cyclonedx-json"),
            require_auth=os.environ.get("REQUIRE_AUTH", "false").lower() in {
                "1",
                "true",
                "yes",
            },
        )
