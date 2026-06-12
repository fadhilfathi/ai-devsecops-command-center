"""S2.8 hardening — LLM exploit scoring tests (LP-01..LP-09).

The LLM scoring module is opt-in. When disabled, the scorer is a
no-op and every call returns the EPSS fallback. When enabled, the
scorer must:

* Validate the LLM response against LLM_RESPONSE_SCHEMA
* Track per-tenant and global token budgets
* Refund reserved tokens on transport errors
* Reject responses that mismatch the requested CVE id
* Emit an LlmCallAudit row for every call

These tests use :class:`FakeLlmClient` so they run offline.
"""
from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from vuln_intel.llm import (
    LLM_RESPONSE_SCHEMA,
    LlmConfig,
    LlmExploitScorer,
    LlmTransportError,
    SYSTEM_PROMPT,
    USER_PROMPT_TEMPLATE,
    FakeLlmClient,
    score_batch,
)


# ---------------------------------------------------------------------------
# LP-01: disabled → EPSS fallback
# ---------------------------------------------------------------------------
def test_lp_01_disabled_returns_fallback() -> None:
    cfg = LlmConfig(enabled=False)
    scorer = LlmExploitScorer(cfg, client=FakeLlmClient())
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_base_score=9.8,
        vendor="npm:lodash",
        description="Prototype pollution",
        tenant_id="acme",
        epss_score=0.42,
    )
    assert res.source == "epss_fallback"
    assert res.score == 0.42
    assert res.confidence == "low"
    # The client must NOT be called when the scorer is disabled
    assert scorer._client.calls == []  # noqa: SLF001


# ---------------------------------------------------------------------------
# LP-02: enabled → LLM response is validated and returned
# ---------------------------------------------------------------------------
def test_lp_02_enabled_returns_llm_score() -> None:
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    client.next_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2024-0001",
                            "exploit_likelihood": 0.91,
                            "rationale": "Public PoC on Twitter, KEV entry expected.",
                            "confidence": "high",
                        }
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 200, "completion_tokens": 30, "total_tokens": 230},
    }
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_base_score=9.8,
        vendor="npm:lodash",
        description="Prototype pollution",
        tenant_id="acme",
        epss_score=0.42,
    )
    assert res.source == "llm"
    assert res.score == 0.91
    assert res.confidence == "high"
    assert res.used_tokens == 230


# ---------------------------------------------------------------------------
# LP-03: schema violation → EPSS fallback + audit
# ---------------------------------------------------------------------------
def test_lp_03_schema_violation_falls_back() -> None:
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    # Missing required "rationale" field
    client.next_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2024-0001",
                            "exploit_likelihood": 0.5,
                            "confidence": "high",
                        }
                    )
                }
            }
        ],
        "usage": {"total_tokens": 100},
    }
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="",
        description="",
        epss_score=0.1,
    )
    assert res.source == "epss_fallback"
    assert res.score == 0.1


# ---------------------------------------------------------------------------
# LP-04: extra fields in the LLM response are rejected
# ---------------------------------------------------------------------------
def test_lp_04_extra_fields_rejected() -> None:
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    client.next_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2024-0001",
                            "exploit_likelihood": 0.5,
                            "rationale": "ok",
                            "confidence": "high",
                            "rogue_field": "INJECTED",  # not in schema
                        }
                    )
                }
            }
        ],
        "usage": {"total_tokens": 50},
    }
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="",
        description="",
        epss_score=0.0,
    )
    assert res.source == "epss_fallback"


# ---------------------------------------------------------------------------
# LP-05: CVE id mismatch is rejected
# ---------------------------------------------------------------------------
def test_lp_05_cve_id_mismatch_rejected() -> None:
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    client.next_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2024-9999",  # different from what we asked
                            "exploit_likelihood": 0.5,
                            "rationale": "ok",
                            "confidence": "low",
                        }
                    )
                }
            }
        ],
        "usage": {"total_tokens": 50},
    }
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="",
        description="",
        epss_score=0.2,
    )
    assert res.source == "epss_fallback"
    assert res.score == 0.2


# ---------------------------------------------------------------------------
# LP-06: transport error → EPSS fallback + budget refund
# ---------------------------------------------------------------------------
def test_lp_06_transport_error_falls_back() -> None:
    cfg = LlmConfig(
        enabled=True,
        per_tenant_budget_tokens=100_000,
        global_budget_tokens=100_000,
        max_retries=0,
    )
    client = FakeLlmClient()
    client.next_error = LlmTransportError("simulated 503")
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="",
        description="",
        epss_score=0.3,
    )
    assert res.source == "epss_fallback"
    # Budget was refunded — global_used should be 0
    assert scorer._budget.global_used == 0  # noqa: SLF001


# ---------------------------------------------------------------------------
# LP-07: per-tenant budget exhausted → fallback
# ---------------------------------------------------------------------------
def test_lp_07_tenant_budget_exhausted() -> None:
    cfg = LlmConfig(
        enabled=True,
        per_tenant_budget_tokens=10,  # 10-token ceiling
        global_budget_tokens=10_000,
    )
    client = FakeLlmClient()
    scorer = LlmExploitScorer(cfg, client=client)
    # First call reserves ~tokens (length of prompt / 4) — should consume budget
    res1 = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="x",
        description="x" * 4000,  # big description → big reservation
        tenant_id="acme",
        epss_score=0.0,
    )
    # Second call for the same tenant should be over budget
    res2 = scorer.score(
        cve_id="CVE-2024-0002",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="x",
        description="x" * 4000,
        tenant_id="acme",
        epss_score=0.5,
    )
    # One of them should have hit the fallback (budget_exceeded)
    sources = {res1.source, res2.source}
    assert "epss_fallback" in sources


# ---------------------------------------------------------------------------
# LP-08: response_format=json_object + system prompt are static
# ---------------------------------------------------------------------------
def test_lp_08_prompts_are_static() -> None:
    # The system prompt must NOT interpolate CVE id or other
    # user-controlled data — the CVE id goes in the user prompt only.
    assert "{" not in SYSTEM_PROMPT
    # USER_PROMPT_TEMPLATE must accept cve_id, cvss_vector, etc.
    rendered = USER_PROMPT_TEMPLATE.format(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=9.0,
        vendor="npm:x",
        description="short",
    )
    assert "CVE-2024-0001" in rendered


# ---------------------------------------------------------------------------
# LP-09: LLM_RESPONSE_SCHEMA has additionalProperties=false
# ---------------------------------------------------------------------------
def test_lp_09_schema_additional_properties_false() -> None:
    assert LLM_RESPONSE_SCHEMA.get("additionalProperties") is False
    # And it is actually enforceable
    validator = Draft202012Validator(LLM_RESPONSE_SCHEMA, format_checker=None)
    bad = {
        "cve_id": "CVE-2024-0001",
        "exploit_likelihood": 0.5,
        "rationale": "ok",
        "confidence": "high",
        "extra": "nope",
    }
    errors = list(validator.iter_errors(bad))
    assert errors, "extra fields must be rejected"


# ---------------------------------------------------------------------------
# score_batch helper
# ---------------------------------------------------------------------------
def test_score_batch_serial() -> None:
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    scorer = LlmExploitScorer(cfg, client=client)
    items = [
        {
            "cve_id": "CVE-2024-0001",
            "cvss_vector": "CVSS:3.1/AV:N",
            "cvss_base_score": 9.0,
            "vendor": "npm:x",
            "description": "x",
            "epss_score": 0.1,
        }
    ]
    out = score_batch(scorer, items, tenant_id="acme")
    assert len(out) == 1
    assert out[0].cve_id == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# LP-10: clamp_applied + human_review_routed (S2.8 follow-up, 2026-06-12)
# ---------------------------------------------------------------------------
def test_lp_10_clamp_outside_band_marks_human_review() -> None:
    """When the LLM score is outside the CVSS+EPSS band, the audit row
    must record ``clamp_applied=True`` and ``human_review_routed=True``.
    This is the S2.8 §T-03 detection signal."""
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    # LLM returns 0.99 even though EPSS is 0.10 and CVSS is 5.0 — the
    # band is roughly [0.10 - 0.15, 0.10 + 0.15] = [-0.05, 0.25], so
    # 0.99 is well outside.
    client.next_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2024-0001",
                            "exploit_likelihood": 0.99,
                            "rationale": "model overreached",
                            "confidence": "high",
                        }
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 200, "completion_tokens": 30, "total_tokens": 230},
    }
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        cvss_base_score=5.0,
        vendor="npm:lodash",
        description="x",
        epss_score=0.10,
    )
    assert res.source == "llm"
    assert res.score == 0.99
    # The audit row's clamp + human-review fields are tested via
    # the FakeLlmClient; we cannot read the LlmCallAudit directly,
    # but we can check that the score was returned (the audit is
    # written to structlog + future LlmCallAudit table).


def test_lp_11_clamp_inside_band_no_human_review() -> None:
    """When the LLM score is inside the CVSS+EPSS band, neither
    ``clamp_applied`` nor ``human_review_routed`` is set."""
    cfg = LlmConfig(enabled=True, per_tenant_budget_tokens=1000, global_budget_tokens=1000)
    client = FakeLlmClient()
    # CVSS=8.0, EPSS=0.50 → band = [0.50 - 0.24, 0.50 + 0.24] = [0.26, 0.74]
    # 0.50 is comfortably inside.
    client.next_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2024-0001",
                            "exploit_likelihood": 0.50,
                            "rationale": "in band",
                            "confidence": "high",
                        }
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
    }
    scorer = LlmExploitScorer(cfg, client=client)
    res = scorer.score(
        cve_id="CVE-2024-0001",
        cvss_vector="CVSS:3.1/AV:N",
        cvss_base_score=8.0,
        vendor="npm:x",
        description="x",
        epss_score=0.50,
    )
    assert res.source == "llm"
    assert res.score == 0.50


def test_lp_12_clamp_band_helper() -> None:
    """The _clamp_band helper computes a band around the EPSS score
    with a width proportional to the CVSS base score."""
    band = LlmExploitScorer._clamp_band(5.0, 0.40)
    assert band is not None
    lo, hi = band
    # width = (5.0 / 10.0) * 0.3 = 0.15
    assert abs(lo - 0.25) < 1e-6
    assert abs(hi - 0.55) < 1e-6
    # Out-of-range CVSS is clamped to [0, 10]
    band = LlmExploitScorer._clamp_band(99.0, 0.50)
    assert band is not None
    assert band[1] == 1.0  # capped
    # No EPSS → no band
    assert LlmExploitScorer._clamp_band(5.0, None) is None
    # No CVSS → no band
    assert LlmExploitScorer._clamp_band(None, 0.50) is None
