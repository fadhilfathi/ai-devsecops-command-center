"""Service configuration for vuln-intel.

All settings are read from environment variables (12-factor). The
:class:`Settings` model is a ``pydantic-settings`` v2 model so values can
be overridden in tests via dependency injection.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Top-level configuration for the vuln-intel service."""

    model_config = SettingsConfigDict(
        env_prefix="VULN_INTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---------------------------------------------------------------- runtime
    service_name: str = Field(default="vuln-intel", frozen=True)
    service_version: str = Field(default="0.1.0", frozen=True)
    env: str = Field(default="dev", pattern=r"^(dev|staging|prod)$")
    tenant_id: str = Field(default="default", min_length=1, max_length=64)

    host: str = Field(default="0.0.0.0")  # noqa: S104 — bind inside the cluster
    port: int = Field(default=4008, ge=1, le=65535)

    # ---------------------------------------------------------------- storage
    data_dir: Path = Field(default=Path("./data"))
    store_filename: str = Field(default="cve-store.jsonl")
    store_max_bytes: int = Field(default=512 * 1024 * 1024)  # 512 MiB

    # ---------------------------------------------------------------- sources
    nvd_api_key: str | None = Field(default=None)
    github_token: str | None = Field(default=None)
    nvd_base_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    ghsa_base_url: str = Field(default="https://api.github.com/advisories")
    osv_base_url: str = Field(default="https://api.osv.dev/v1")
    epss_base_url: str = Field(default="https://api.first.org/data/v1/epss")
    kev_base_url: str = Field(default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")

    nvd_request_timeout_s: float = Field(default=15.0, ge=1.0, le=60.0)
    ghsa_request_timeout_s: float = Field(default=15.0, ge=1.0, le=60.0)
    osv_request_timeout_s: float = Field(default=10.0, ge=1.0, le=60.0)
    epss_request_timeout_s: float = Field(default=10.0, ge=1.0, le=60.0)
    kev_request_timeout_s: float = Field(default=15.0, ge=1.0, le=60.0)

    # ---------------------------------------------------------------- caching
    nvd_cache_ttl_s: int = Field(default=86_400, ge=0)
    ghsa_cache_ttl_s: int = Field(default=86_400, ge=0)
    osv_cache_ttl_s: int = Field(default=86_400, ge=0)
    epss_cache_ttl_s: int = Field(default=3_600, ge=0)
    kev_cache_ttl_s: int = Field(default=3_600, ge=0)

    # ---------------------------------------------------------------- scheduler
    ingest_schedule_cron: str = Field(default="0 3 * * *")  # daily at 03:00 UTC
    ingest_enabled: bool = Field(default=True)

    # ---------------------------------------------------------------- observability
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    otel_endpoint: str = Field(default="http://localhost:4317")
    metrics_enabled: bool = Field(default=True)

    # ---------------------------------------------------------------- auth
    auth_jwt_secret: str | None = Field(default=None)
    auth_jwt_algorithm: str = Field(default="HS256")
    auth_jwt_audience: str = Field(default="ai-devsecops")
    auth_required: bool = Field(default=False)  # set true in prod

    @property
    def store_path(self) -> Path:
        return self.data_dir / self.store_filename


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a process-wide singleton :class:`Settings` instance."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the cached :class:`Settings` instance — used in tests."""
    get_settings.cache_clear()
