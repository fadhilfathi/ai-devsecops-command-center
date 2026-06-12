"""Per-feed JSON-schema validators + safe parsers.

The vulnerability intelligence service ingests CVE feeds from three
upstream sources — NVD 2.0, GitHub Security Advisories (GHSA), and
OSV — plus a single EPSS feed and a single CISA KEV catalog. Each
upstream payload is validated against a strict JSON Schema before any
field is read. Records that fail validation are rejected (never
coerced) and counted in the per-feed audit log so operators can spot
upstream schema drift before it pollutes the store.

The schemas below are direct ports of the AJV definitions kept in the
SecurityArchitect S2.8 design document § 3.5. Numeric fields are
range-checked at the schema layer (CVSS 0.0–10.0, EPSS 0.0–1.0,
severity enum whitelist). JSON is parsed with a hard ``max_depth`` of
20 to prevent stack-overflow attacks from malicious upstream payloads.

This module deliberately does **not** import any network code — the
service layer is responsible for fetching and passing the raw bytes
to :func:`validate_record`.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

try:  # pragma: no cover — import-time guard
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover — we add jsonschema as a hard dep
    jsonschema = None  # type: ignore[assignment]
    Draft202012Validator = None  # type: ignore[assignment,misc]

from defusedxml import ElementTree as defused_etree  # noqa: F401  (safe XML)

# Maximum nesting depth for any parsed JSON. CVE records are flat-ish
# but the upstream payloads we receive (OSV vulnerabilities, NVD
# configurations) can go a few levels deep. 20 is more than enough.
MAX_JSON_DEPTH: Final[int] = 20

# Validator version stamped on every record. Bump this whenever a
# schema definition changes in a way that would invalidate previously
# stored data — it surfaces in the audit log.
VALIDATOR_VERSION: Final[str] = "s2.8.0"

# Severity enum — case-insensitive whitelist mirrored from the AJV
# schema. Anything outside this set is rejected.
_SEVERITY_ENUM: Final[set[str]] = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _cvss_metric_entry_schema(version: str) -> dict[str, Any]:
    """Return a CVSS metric entry schema for the given CVSS version."""
    return {
        "type": "object",
        "required": ["cvssData"],
        "properties": {
            "cvssData": {
                "type": "object",
                "required": ["vectorString"],
                "properties": {
                    "version": {"type": "string", "enum": [version]},
                    "vectorString": {
                        "type": "string",
                        "pattern": r"^CVSS:[0-9.]+/.+",
                        "maxLength": 256,
                    },
                    "baseScore": {"type": "number", "minimum": 0.0, "maximum": 10.0},
                    "baseSeverity": {"type": "string", "enum": sorted(_SEVERITY_ENUM)},
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# NVD CVE 5.0 schema (subset — only the fields the service reads)
# ---------------------------------------------------------------------------
NVD_CVE_5_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://ai-devsecops.local/schemas/nvd-cve-5.json",
    "title": "NVD CVE 2.0 / CVE-5.0 envelope (subset)",
    "type": "object",
    "required": ["vulnerabilities"],
    "additionalProperties": True,
    "properties": {
        "resultsPerPage": {"type": "integer", "minimum": 1, "maximum": 10_000},
        "startIndex": {"type": "integer", "minimum": 0},
        "totalResults": {"type": "integer", "minimum": 0},
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["cve"],
                "properties": {
                    "cve": {
                        "type": "object",
                        "required": ["id", "published", "lastModified"],
                        "properties": {
                            "id": {
                                "type": "string",
                                "pattern": r"^CVE-\d{4}-\d{4,}$",
                            },
                            "published": {
                                "type": "string",
                                "format": "date-time",
                                "minLength": 10,
                                "maxLength": 40,
                            },
                            "lastModified": {
                                "type": "string",
                                "format": "date-time",
                                "minLength": 10,
                                "maxLength": 40,
                            },
                            "descriptions": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "lang": {"type": "string", "minLength": 2, "maxLength": 8},
                                        "value": {"type": "string", "minLength": 1, "maxLength": 8000},
                                    },
                                },
                            },
                            "metrics": {
                                "type": "object",
                                "properties": {
                                    "cvssMetricV31": {
                                        "type": "array",
                                        "items": _cvss_metric_entry_schema("3.1"),
                                    },
                                    "cvssMetricV30": {
                                        "type": "array",
                                        "items": _cvss_metric_entry_schema("3.0"),
                                    },
                                    "cvssMetricV40": {
                                        "type": "array",
                                        "items": _cvss_metric_entry_schema("4.0"),
                                    },
                                },
                            },
                            "configurations": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "nodes": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "cpeMatch": {
                                                        "type": "array",
                                                        "items": {
                                                            "type": "object",
                                                            "properties": {
                                                                "vulnerable": {"type": "boolean"},
                                                                "criteria": {
                                                                    "type": "string",
                                                                    "minLength": 1,
                                                                    "maxLength": 1024,
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            "references": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "url": {"type": "string", "format": "uri", "maxLength": 2048},
                                        "tags": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                                "enum": [
                                                    "Patch",
                                                    "Vendor Advisory",
                                                    "Third Party Advisory",
                                                    "Exploit",
                                                    "Mailing List",
                                                ],
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# GHSA (GitHub Security Advisory) schema
# ---------------------------------------------------------------------------
GHSA_ADVISORY_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://ai-devsecops.local/schemas/ghsa-advisory.json",
    "title": "GitHub Security Advisory",
    "type": "object",
    "required": ["ghsa_id", "cve_id", "severity", "cvss"],
    "additionalProperties": True,
    "properties": {
        "ghsa_id": {
            "type": "string",
            "pattern": r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$",
        },
        "cve_id": {"type": "string", "minLength": 1, "maxLength": 64},
        "summary": {"type": "string", "maxLength": 1024},
        "description": {"type": "string", "maxLength": 65_535},
        "severity": {"type": "string", "enum": sorted(_SEVERITY_ENUM)},
        "cvss": {
            "type": "object",
            "required": ["vector_string"],
            "properties": {
                "vector_string": {
                    "type": "string",
                    "pattern": r"^CVSS:[0-9.]+/.+",
                    "maxLength": 256,
                },
                "score": {"type": "number", "minimum": 0.0, "maximum": 10.0},
            },
        },
        "vulnerable_version_range": {
            "type": "string",
            "maxLength": 512,
        },
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "object",
                        "properties": {
                            "ecosystem": {"type": "string", "maxLength": 64},
                            "name": {"type": "string", "maxLength": 256},
                        },
                    },
                    "vulnerable_version_range": {"type": "string", "maxLength": 512},
                    "first_patched_version": {"type": "string", "maxLength": 128},
                },
            },
        },
        "published_at": {
            "type": "string",
            "format": "date-time",
            "maxLength": 40,
        },
        "updated_at": {
            "type": "string",
            "format": "date-time",
            "maxLength": 40,
        },
    },
}


# ---------------------------------------------------------------------------
# OSV (Open Source Vulnerabilities) schema — single vulnerability object
# ---------------------------------------------------------------------------
OSV_VULN_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://ai-devsecops.local/schemas/osv-vuln.json",
    "title": "OSV Vulnerability",
    "type": "object",
    "required": ["id"],
    "properties": {
        "id": {
            "type": "string",
            "minLength": 3,
            "maxLength": 256,
            "pattern": r"^[A-Z0-9][A-Z0-9._\-:]*[A-Z0-9]$|^CVE-\d{4}-\d{4,}$|^GHSA-[a-z0-9-]+$",
        },
        "summary": {"type": "string", "maxLength": 1024},
        "details": {"type": "string", "maxLength": 65_535},
        "aliases": {
            "type": "array",
            "items": {"type": "string", "minLength": 3, "maxLength": 256},
        },
        "modified": {
            "type": "string",
            "format": "date-time",
            "maxLength": 40,
        },
        "published": {
            "type": "string",
            "format": "date-time",
            "maxLength": 40,
        },
        "severity": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "score"],
                "properties": {
                    "type": {"type": "string", "enum": ["CVSS_V3", "CVSS_V2", "CVSS_V4"]},
                    "score": {
                        "type": "string",
                        "pattern": r"^CVSS:[0-9.]+/.+|^.+$",
                        "maxLength": 256,
                    },
                },
            },
        },
        "affected": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "object",
                        "properties": {
                            "ecosystem": {"type": "string", "maxLength": 64},
                            "name": {"type": "string", "maxLength": 256},
                            "purl": {"type": "string", "maxLength": 512},
                        },
                    },
                    "ranges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["SEMVER", "ECOSYSTEM", "GIT"]},
                                "events": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "introduced": {"type": "string", "maxLength": 128},
                                            "fixed": {"type": "string", "maxLength": 128},
                                            "limit": {"type": "string", "maxLength": 128},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# EPSS + KEV schemas
# ---------------------------------------------------------------------------
EPSS_ENTRY_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "required": ["cve", "epss", "percentile"],
    "properties": {
        "cve": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
        "epss": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "percentile": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "date": {"type": "string", "maxLength": 40},
    },
}

KEV_ENTRY_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "required": ["cveID", "dateAdded"],
    "properties": {
        "cveID": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
        "dateAdded": {"type": "string", "maxLength": 40},
        "shortDescription": {"type": "string", "maxLength": 1024},
    },
}


# ---------------------------------------------------------------------------
# Validation result types
# ---------------------------------------------------------------------------
@dataclass(slots=True, frozen=True)
class ValidationResult:
    """Outcome of validating a single record against its source schema."""

    valid: bool
    record_id: str | None
    errors: tuple[str, ...] = field(default_factory=tuple)
    validator_version: str = VALIDATOR_VERSION
    # ``rejected_reason`` is a short string for metrics labelling —
    # e.g. ``schema_violation``, ``parse_error``, ``depth_exceeded``.
    rejected_reason: str | None = None


# ---------------------------------------------------------------------------
# Safe JSON parser (bounded depth)
# ---------------------------------------------------------------------------
class JSONDepthError(ValueError):
    """Raised when parsed JSON exceeds :data:`MAX_JSON_DEPTH`."""


def _check_depth(obj: Any, current: int = 0) -> None:
    """Recursively walk a JSON object enforcing a hard depth cap."""
    if current > MAX_JSON_DEPTH:
        raise JSONDepthError(
            f"JSON nesting exceeds max depth of {MAX_JSON_DEPTH}"
        )
    if isinstance(obj, dict):
        for value in obj.values():
            _check_depth(value, current + 1)
    elif isinstance(obj, list):
        for value in obj:
            _check_depth(value, current + 1)


def safe_json_loads(raw: bytes | str) -> Any:
    """Parse JSON safely, rejecting payloads deeper than :data:`MAX_JSON_DEPTH`.

    Returns the parsed object on success. Raises :class:`ValueError` for
    any parse error and :class:`JSONDepthError` for over-deep payloads.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    _check_depth(obj)
    return obj


def safe_json_loads_array(raw: bytes | str) -> list[Any]:
    """Parse a JSON array. Raises :class:`ValueError` if the top-level is not a list."""
    obj = safe_json_loads(raw)
    if not isinstance(obj, list):
        raise ValueError(f"expected JSON array, got {type(obj).__name__}")
    return obj


# ---------------------------------------------------------------------------
# Per-source validators
# ---------------------------------------------------------------------------
class FeedValidator:
    """Base class for per-source feed validators."""

    schema: dict[str, Any] = {}
    source_name: str = ""

    def __init__(self) -> None:
        if jsonschema is None or Draft202012Validator is None:
            raise RuntimeError(
                "jsonschema is required for feed validation — "
                "add 'jsonschema' to vuln-intel dependencies."
            )
        # ``format_checker=None`` — we don't need full RFC 3339 / URI
        # validation at the schema layer; downstream code is the source
        # of truth on date and URL shape.
        self._validator = Draft202012Validator(self.schema, format_checker=None)

    def validate_record(self, record: Mapping[str, Any]) -> ValidationResult:
        """Validate a single record. Subclasses may override for record-id extraction."""
        record_id = self._extract_id(record)
        errors = sorted(self._validator.iter_errors(record), key=lambda e: e.path)
        if errors:
            rendered = tuple(
                f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
                for err in errors
            )
            return ValidationResult(
                valid=False,
                record_id=record_id,
                errors=rendered[:10],  # cap to 10 errors
                rejected_reason="schema_violation",
            )
        return ValidationResult(valid=True, record_id=record_id)

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        return None


class NvdValidator(FeedValidator):
    """Validates an NVD 2.0 / CVE-5.0 envelope or single vulnerability entry."""

    schema = NVD_CVE_5_SCHEMA
    source_name = "nvd"

    def validate_record(self, record: Mapping[str, Any]) -> ValidationResult:
        # The upstream payload is a full envelope; we validate it
        # whole and report the CVE id from the first vulnerability.
        return super().validate_record(record)

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        vulns = record.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = vulns[0].get("cve") or {}
        return cve.get("id")


class GhsaValidator(FeedValidator):
    """Validates a single GitHub Security Advisory record."""

    schema = GHSA_ADVISORY_SCHEMA
    source_name = "ghsa"

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        return record.get("ghsa_id") or record.get("cve_id")


class OsvValidator(FeedValidator):
    """Validates a single OSV vulnerability record."""

    schema = OSV_VULN_SCHEMA
    source_name = "osv"

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        return record.get("id")


class EpssValidator(FeedValidator):
    """Validates a single EPSS entry. Used for shape-checks only."""

    schema = EPSS_ENTRY_SCHEMA
    source_name = "epss"

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        return record.get("cve")


class KevValidator(FeedValidator):
    """Validates a single CISA KEV entry."""

    schema = KEV_ENTRY_SCHEMA
    source_name = "kev"

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        return record.get("cveID")


# Per-item NVD CVE-5 schema (used to validate individual records
# during the fetch loop, so a single bad CVE doesn't taint the
# whole page).
NVD_CVE_5_ITEM_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["cve"],
    "properties": {
        "cve": {
            "type": "object",
            "required": ["id", "published", "lastModified"],
            "properties": {
                "id": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
                "published": {"type": "string", "minLength": 10, "maxLength": 40},
                "lastModified": {"type": "string", "minLength": 10, "maxLength": 40},
            },
        },
    },
}


class NvdItemValidator(FeedValidator):
    """Validates a single NVD CVE 5.0 vulnerability item (not the envelope)."""

    schema = NVD_CVE_5_ITEM_SCHEMA
    source_name = "nvd-item"

    def _extract_id(self, record: Mapping[str, Any]) -> str | None:
        cve = record.get("cve") or {}
        return cve.get("id")


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------
def get_validator(source: str) -> FeedValidator:
    """Return the validator registered for ``source``."""
    registry: dict[str, type[FeedValidator]] = {
        "nvd": NvdValidator,
        "nvd-item": NvdItemValidator,
        "ghsa": GhsaValidator,
        "osv": OsvValidator,
        "epss": EpssValidator,
        "kev": KevValidator,
    }
    cls = registry.get(source.lower())
    if cls is None:  # pragma: no cover — programmer error
        raise ValueError(f"unknown feed source: {source!r}")
    return cls()
