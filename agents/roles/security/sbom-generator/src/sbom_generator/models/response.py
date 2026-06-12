"""Response models for the SBOM generator HTTP service."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from sbom_generator.models.sbom import SBOM, SBOMFormat


class FormattedSBOM(BaseModel):
    format: SBOMFormat
    media_type: str
    body: str
    byte_size: int


class GenerateResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    accepted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    source_type: str
    source_value: str
    format: SBOMFormat
    components_count: int = 0
    distinct_licenses: int = 0
    formats: List[FormattedSBOM] = Field(default_factory=list)
    sbom: Optional[SBOM] = None
    warnings: List[str] = Field(default_factory=list)
    bus_event_id: Optional[str] = None

    def to_summary(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "job_id": self.job_id,
            "format": self.format.value,
            "components_count": self.components_count,
            "distinct_licenses": self.distinct_licenses,
            "duration_ms": self.duration_ms,
            "warnings": self.warnings,
        }


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    syft_path: str
    syft_version: Optional[str] = None
    uptime_seconds: float
    bus_connected: bool = False
    active_jobs: int = 0
    max_concurrent_jobs: int
    checks: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None
