"""Configuration for dependency-intel."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DEP_INTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    service_name: str = Field(default="dependency-intel", frozen=True)
    service_version: str = Field(default="0.1.0", frozen=True)
    env: str = Field(default="dev", pattern=r"^(dev|staging|prod)$")
    tenant_id: str = Field(default="default", min_length=1, max_length=64)

    host: str = Field(default="0.0.0.0")  # noqa: S104
    port: int = Field(default=4009, ge=1, le=65535)

    data_dir: Path = Field(default=Path("./data"))
    graph_filename: str = Field(default="graphs.jsonl")

    # Upstream service
    vuln_intel_url: str = Field(default="http://localhost:4008")
    vuln_intel_timeout_s: float = Field(default=10.0, ge=1.0, le=60.0)

    # Algorithm knobs
    risk_alpha: float = Field(default=0.6, ge=0.0, le=1.0)
    risk_damping: float = Field(default=0.85, ge=0.0, le=1.0)
    risk_baseline: float = Field(default=5.0, ge=0.0, le=100.0)
    max_graph_nodes: int = Field(default=50_000, ge=10)
    max_graph_edges: int = Field(default=500_000, ge=10)

    # Observability
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    otel_endpoint: str = Field(default="http://localhost:4317")
    metrics_enabled: bool = Field(default=True)

    # Auth
    auth_jwt_secret: str | None = Field(default=None)
    auth_jwt_algorithm: str = Field(default="HS256")
    auth_jwt_audience: str = Field(default="ai-devsecops")
    auth_required: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
