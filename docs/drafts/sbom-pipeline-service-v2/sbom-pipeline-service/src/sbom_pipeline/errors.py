"""Typed exception hierarchy for the SBOM pipeline service.

Each exception carries an explicit ``code`` so HTTP responses can map
errors to status codes and the event bus can propagate them to
downstream consumers without losing semantics.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class SBOMError(Exception):
    """Base class for all SBOM pipeline errors."""

    code: str = "sbom_error"
    http_status: int = 500

    def __init__(
        self,
        message: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


class ValidationError(SBOMError):
    code = "validation_error"
    http_status = 400


class SourceNotFoundError(SBOMError):
    code = "source_not_found"
    http_status = 404


class SBOMNotFoundError(SBOMError):
    code = "sbom_not_found"
    http_status = 404


class SyftNotFoundError(SBOMError):
    code = "syft_not_found"
    http_status = 500


class SyftExecutionError(SBOMError):
    code = "syft_execution_error"
    http_status = 502


class SyftTimeoutError(SBOMError):
    code = "syft_timeout"
    http_status = 504


class BusPublishError(SBOMError):
    code = "bus_publish_error"
    http_status = 502


class StorageError(SBOMError):
    code = "storage_error"
    http_status = 500


class AuthenticationError(SBOMError):
    """Caller failed to present a valid authentication token."""

    code = "authentication_error"
    http_status = 401


class AuthorizationError(SBOMError):
    """Caller's identity is valid but lacks the required role/scope."""

    code = "authorization_error"
    http_status = 403
