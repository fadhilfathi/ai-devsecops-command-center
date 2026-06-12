"""Application settings — env-driven, Pydantic-settings.

The settings are loaded once at boot. The :func:`create_app` factory
takes an explicit :class:`Settings` instance so tests can override
any value without monkey-patching modules.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the SBOM pipeline service."""

    model_config = SettingsConfigDict(
        env_prefix="SBOM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- HTTP
    host: str = "0.0.0.0"
    port: int = 4007
    workers: int = 1
    log_level: str = "INFO"

    # ---- Syft
    syft_binary: str = "syft"
    request_timeout_seconds: int = 600
    max_concurrent_scans: int = 4

    # ---- Storage
    db_url: str = "sqlite+aiosqlite:///./backend/data/sbom.db"
    object_store_url: str = "fs://./backend/data/sbom-store"
    data_dir: Path = Path("./backend/data")

    # ---- Bus
    bus_url: str = "nats://localhost:4222"
    bus_subject_prefix: str = "security.sbom"
    bus_requested_subject: str = "security.sbom.requested.v1"

    # ---- Auth
    require_auth: bool = False

    # ---- Service identity
    service_name: str = "sbom-pipeline"
    service_version: str = "1.0.0"

    # ---- Signing (production only)
    cosign_enabled: bool = False
    cosign_key: Optional[str] = None  # cosign private key path

    def object_store_parsed(self) -> tuple[str, str]:
        """Split ``s3://bucket/prefix`` or ``fs://./path`` into (kind, path)."""
        if self.object_store_url.startswith("s3://"):
            return "s3", self.object_store_url[len("s3://"):]
        if self.object_store_url.startswith("fs://"):
            return "fs", self.object_store_url[len("fs://"):]
        # Default: treat as a filesystem path.
        return "fs", self.object_store_url


from typing import Optional  # noqa: E402  (placed here to keep pydantic-settings import first)
