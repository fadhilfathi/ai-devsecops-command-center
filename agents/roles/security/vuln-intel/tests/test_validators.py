"""S2.8 hardening — feed validation tests (CF-01..CF-05).

The ``CF-`` prefix refers to the SecurityArchitect's cross-source
consensus + feed-validation test plan.

Tests in this file exercise the per-feed JSON-Schema validators and
the depth-bounded JSON parser. They are intentionally pure-Python
(no FastAPI, no network) so they run in the pre-deploy CI gate.
"""
from __future__ import annotations

import json

import pytest

from vuln_intel.validators import (
    EpssValidator,
    FeedValidator,
    GhsaValidator,
    JSONDepthError,
    KevValidator,
    MAX_JSON_DEPTH,
    NVD_CVE_5_SCHEMA,
    NVD_CVE_5_ITEM_SCHEMA,
    NvdItemValidator,
    NvdValidator,
    OsvValidator,
    ValidationResult,
    get_validator,
    safe_json_loads,
    safe_json_loads_array,
)


# ---------------------------------------------------------------------------
# CF-01: well-formed NVD envelope passes
# ---------------------------------------------------------------------------
def test_cf_01_nvd_envelope_valid() -> None:
    """A minimal but spec-compliant NVD envelope must pass validation."""
    payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                }
            }
        ],
    }
    v = NvdValidator()
    res = v.validate_record(payload)
    assert res.valid, res.errors
    assert res.record_id == "CVE-2024-1234"


# ---------------------------------------------------------------------------
# CF-02: malformed NVD envelope (bad CVE id) is rejected
# ---------------------------------------------------------------------------
def test_cf_02_nvd_envelope_bad_id_rejected() -> None:
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "not-a-cve", "published": "2024-01-01", "lastModified": "2024-01-02"}}
        ]
    }
    v = NvdValidator()
    res = v.validate_record(payload)
    assert not res.valid
    assert res.rejected_reason == "schema_violation"
    assert res.errors


# ---------------------------------------------------------------------------
# CF-03: NVD per-item validator
# ---------------------------------------------------------------------------
def test_cf_03_nvd_item_validator() -> None:
    good = {"cve": {"id": "CVE-2024-9999", "published": "2024-05-01", "lastModified": "2024-05-02"}}
    bad = {"cve": {"id": "XXX"}}
    v = NvdItemValidator()
    assert v.validate_record(good).valid
    assert not v.validate_record(bad).valid


# ---------------------------------------------------------------------------
# CF-04: GHSA + OSV + EPSS + KEV round-trip
# ---------------------------------------------------------------------------
def test_cf_04_ghsa_osv_epss_kev_validators() -> None:
    ghsa = GhsaValidator()
    assert ghsa.validate_record(
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2024-1111",
            "severity": "HIGH",
            "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
        }
    ).valid
    assert not ghsa.validate_record(
        {"ghsa_id": "GHSA-bad", "cve_id": "CVE-2024-1111", "severity": "SUPER", "cvss": {"vector_string": ""}}
    ).valid

    osv = OsvValidator()
    assert osv.validate_record(
        {
            "id": "CVE-2024-2222",
            "modified": "2024-05-01T00:00:00Z",
            "published": "2024-05-01T00:00:00Z",
        }
    ).valid
    assert not osv.validate_record({"id": "x"}).valid  # id too short

    assert EpssValidator().validate_record(
        {"cve": "CVE-2024-3333", "epss": 0.5, "percentile": 0.9}
    ).valid
    assert not EpssValidator().validate_record(
        {"cve": "CVE-2024-3333", "epss": 1.5, "percentile": 0.9}  # > 1.0
    ).valid

    assert KevValidator().validate_record(
        {"cveID": "CVE-2024-4444", "dateAdded": "2024-06-01"}
    ).valid


# ---------------------------------------------------------------------------
# CF-05: numeric range-checked fields
# ---------------------------------------------------------------------------
def test_cf_05_numeric_range_checks() -> None:
    # CVSS base score > 10 must be rejected
    ghsa = GhsaValidator()
    res = ghsa.validate_record(
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2024-5555",
            "severity": "CRITICAL",
            "cvss": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 11.5,  # out of range
            },
        }
    )
    assert not res.valid
    # EPSS > 1.0 must be rejected
    epss = EpssValidator()
    assert not epss.validate_record(
        {"cve": "CVE-2024-6666", "epss": 2.0, "percentile": 0.5}
    ).valid
    # EPSS < 0.0 must be rejected
    assert not epss.validate_record(
        {"cve": "CVE-2024-6666", "epss": -0.1, "percentile": 0.5}
    ).valid
    # Invalid severity must be rejected
    assert not ghsa.validate_record(
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": "CVE-2024-7777",
            "severity": "CATASTROPHIC",
            "cvss": {"vector_string": "CVSS:3.1/AV:N", "score": 5.0},
        }
    ).valid


# ---------------------------------------------------------------------------
# safe_json_loads depth enforcement
# ---------------------------------------------------------------------------
def test_safe_json_depth_limit() -> None:
    # Exactly at the limit should pass
    deep = "[" * MAX_JSON_DEPTH + "1" + "]" * MAX_JSON_DEPTH
    assert safe_json_loads(deep) is not None

    # Beyond the limit raises
    too_deep = "[" * (MAX_JSON_DEPTH + 5) + "1" + "]" * (MAX_JSON_DEPTH + 5)
    with pytest.raises(JSONDepthError):
        safe_json_loads(too_deep)


def test_safe_json_rejects_malformed() -> None:
    with pytest.raises(ValueError):
        safe_json_loads("not json")
    with pytest.raises(ValueError):
        safe_json_loads_array("{}")


def test_safe_json_accepts_array() -> None:
    arr = safe_json_loads_array(b'[{"a": 1}, {"b": 2}]')
    assert len(arr) == 2


# ---------------------------------------------------------------------------
# get_validator factory
# ---------------------------------------------------------------------------
def test_get_validator_factory() -> None:
    assert isinstance(get_validator("nvd"), NvdValidator)
    assert isinstance(get_validator("nvd-item"), NvdItemValidator)
    assert isinstance(get_validator("ghsa"), GhsaValidator)
    assert isinstance(get_validator("osv"), OsvValidator)
    assert isinstance(get_validator("epss"), EpssValidator)
    assert isinstance(get_validator("kev"), KevValidator)
    with pytest.raises(ValueError):
        get_validator("bogus-source")


# ---------------------------------------------------------------------------
# NVD schema structural sanity
# ---------------------------------------------------------------------------
def test_nvd_schemas_have_required_fields() -> None:
    assert NVD_CVE_5_SCHEMA["type"] == "object"
    assert "vulnerabilities" in NVD_CVE_5_SCHEMA["required"]
    assert NVD_CVE_5_ITEM_SCHEMA["required"] == ["cve"]


# ---------------------------------------------------------------------------
# ValidationResult is hashable + immutable
# ---------------------------------------------------------------------------
def test_validation_result_is_frozen() -> None:
    r = ValidationResult(valid=True, record_id="CVE-2024-9999")
    with pytest.raises((AttributeError, TypeError)):
        r.valid = False  # type: ignore[misc]
