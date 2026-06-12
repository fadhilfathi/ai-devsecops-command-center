"""Opt-in LLM exploit scoring for the vulnerability intelligence service.

S2.8 introduces an LLM-based exploit-prediction signal that augments
EPSS. The signal is **opt-in**: it is disabled by default and must be
explicitly enabled via ``VULN_INTEL_LLM_ENABLED=1`` (or via
:data:`LLMConfig.from_env`). When disabled, the module is a no-op and
:class:`LlmExploitScorer.fallback_score` is used everywhere.

Design constraints (all from the SecurityArchitect's S2.8 review):

1. **Strict JSON Schema** validation on every LLM response. Any
   deviation — extra fields, missing fields, type mismatches — is
   treated as a hard failure and triggers the EPSS fallback.
2. **Per-tenant token budget** with a global ceiling. Both limits
   must be set; the scorer refuses to call the model when either is
   exhausted.
3. **Deterministic prompt** — the prompt template is a single string
   constant with no f-string formatting that could let upstream data
   influence the instructions. CVE id and CVSS vector are passed as
   the ``user`` turn only, never as part of the system prompt.
4. **Audit per call** — every LLM call (success or failure) emits a
   :class:`LlmCallAudit` event so the security team can replay
   decisions.
5. **Offline test path** — :class:`FakeLlmClient` lets the test suite
   exercise the contract without hitting a real LLM provider.

The module is provider-agnostic: the caller supplies an
:class:`LlmClient` (or the default :class:`HttpLlmClient`, which posts
to an OpenAI-compatible ``/chat/completions`` endpoint).
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Protocol

from jsonschema import Draft202012Validator  # type: ignore[import-not-found]

from .telemetry import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# JSON Schema for LLM responses — must match exactly. Extra fields
# are rejected.
# ---------------------------------------------------------------------------
LLM_RESPONSE_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://ai-devsecops.local/schemas/llm-exploit-score.json",
    "type": "object",
    "required": ["cve_id", "exploit_likelihood", "rationale", "confidence"],
    "additionalProperties": False,
    "properties": {
        "cve_id": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
        "exploit_likelihood": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
        "rationale": {"type": "string", "minLength": 1, "maxLength": 2000},
        "confidence": {
            "type": "string",
            "enum": ["low", "medium", "high"],
        },
    },
}

# Lock-step validator used on every LLM response.
# ``format_checker=None`` skips RFC 3339 / URI validation at the schema
# layer — the LLM prompt template guarantees the structure, and the
# downstream code is the source of truth for date / URL shape.
_llm_response_validator: Final[Any] = Draft202012Validator(
    LLM_RESPONSE_SCHEMA, format_checker=None
)

# Strict, immutable prompt template. CVE id and CVSS vector are
# intentionally NOT interpolated into the system prompt — the system
# prompt is static so a malicious CVE record cannot inject
# instructions via this channel.
SYSTEM_PROMPT: Final[str] = (
    "You are a security analyst scoring the likelihood that a "
    "publicly disclosed vulnerability will be exploited in the wild "
    "in the next 30 days. Use only the information in the user's "
    "message. Respond with a single JSON object matching the "
    "provided schema. Do not include any other text."
)

USER_PROMPT_TEMPLATE: Final[str] = (
    "CVE id: {cve_id}\n"
    "CVSS vector: {cvss_vector}\n"
    "CVSS base score: {cvss_base_score}\n"
    "Vendor / product: {vendor}\n"
    "Description (truncated to 600 chars):\n{description}\n\n"
    "Respond with JSON only, matching this schema:\n"
    '   {{ "cve_id": "CVE-...","exploit_likelihood": 0.0-1.0,'
    ' "rationale": "<= 2000 chars","confidence": "low|medium|high" }}'
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass(slots=True, frozen=True)
class LlmConfig:
    """Static configuration for the LLM exploit scorer.

    All fields are read once at startup; runtime mutation is not
    supported. ``enabled=False`` short-circuits every scoring call to
    the EPSS fallback.
    """

    enabled: bool = False
    model: str = "gpt-4o-mini"
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 15.0
    max_retries: int = 2
    per_tenant_budget_tokens: int = 100_000
    global_budget_tokens: int = 5_000_000
    cost_per_1k_tokens_micros: int = 200  # 0.2 USD / 1k tokens, conservative

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "LlmConfig":
        """Build an :class:`LlmConfig` from environment variables.

        Required to enable:
            VULN_INTEL_LLM_ENABLED=1
        Optional tuning:
            VULN_INTEL_LLM_MODEL
            VULN_INTEL_LLM_BASE_URL
            VULN_INTEL_LLM_TIMEOUT_SECONDS
            VULN_INTEL_LLM_MAX_RETRIES
            VULN_INTEL_LLM_TENANT_BUDGET_TOKENS
            VULN_INTEL_LLM_GLOBAL_BUDGET_TOKENS
        """
        e = env if env is not None else os.environ
        return cls(
            enabled=_bool_env(e.get("VULN_INTEL_LLM_ENABLED", "0")),
            model=e.get("VULN_INTEL_LLM_MODEL", "gpt-4o-mini"),
            base_url=e.get("VULN_INTEL_LLM_BASE_URL", "https://api.openai.com/v1"),
            timeout_seconds=float(e.get("VULN_INTEL_LLM_TIMEOUT_SECONDS", "15")),
            max_retries=int(e.get("VULN_INTEL_LLM_MAX_RETRIES", "2")),
            per_tenant_budget_tokens=int(
                e.get("VULN_INTEL_LLM_TENANT_BUDGET_TOKENS", "100000")
            ),
            global_budget_tokens=int(
                e.get("VULN_INTEL_LLM_GLOBAL_BUDGET_TOKENS", "5000000")
            ),
            cost_per_1k_tokens_micros=int(
                e.get("VULN_INTEL_LLM_COST_PER_1K_MICROS", "200")
            ),
        )


def _bool_env(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Budget tracker
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class _BudgetTracker:
    """Thread-safe token-budget tracker for LLM calls."""

    per_tenant: dict[str, int] = field(default_factory=dict)
    global_used: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def try_consume(self, tenant_id: str, tokens: int, ceiling: int) -> bool:
        """Reserve ``tokens`` against the tenant and global budgets.

        Returns True if the reservation succeeded. On failure, no
        tokens are deducted.
        """
        if tokens <= 0:
            return True
        with self.lock:
            if self.global_used + tokens > ceiling["global"]:
                return False
            if self.per_tenant.get(tenant_id, 0) + tokens > ceiling["tenant"]:
                return False
            self.per_tenant[tenant_id] = self.per_tenant.get(tenant_id, 0) + tokens
            self.global_used += tokens
            return True

    def refund(self, tenant_id: str, tokens: int) -> None:
        """Return previously-reserved tokens to the budget.

        Used when an LLM call fails after reservation: we never want
        a transient transport error to permanently reduce the budget.
        """
        if tokens <= 0:
            return
        with self.lock:
            self.per_tenant[tenant_id] = max(0, self.per_tenant.get(tenant_id, 0) - tokens)
            self.global_used = max(0, self.global_used - tokens)


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------
@dataclass(slots=True, frozen=True)
class LlmCallAudit:
    """One row in the LLM-call audit log (also emitted to structlog)."""

    call_id: str
    tenant_id: str
    cve_id: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    duration_ms: int
    status: str  # "ok" | "schema_violation" | "budget_exceeded" | "transport_error"
    error: str | None = None
    fallback_used: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass(slots=True, frozen=True)
class LlmScore:
    """Result of an LLM exploit-score lookup."""

    cve_id: str
    score: float
    confidence: str
    rationale: str
    source: str  # "llm" | "epss_fallback"
    used_tokens: int
    call_id: str


# ---------------------------------------------------------------------------
# Client protocol + default HTTP implementation
# ---------------------------------------------------------------------------
class LlmClient(Protocol):
    """Protocol implemented by LLM provider adapters."""

    def chat(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Return the raw chat-completions response as a dict.

        Implementations must raise :class:`LlmTransportError` for
        transport failures. Validation of the response body is the
        caller's job — not the client's.
        """
        ...


class LlmTransportError(RuntimeError):
    """Raised when the LLM provider is unreachable or returns a non-2xx."""


class HttpLlmClient:
    """OpenAI-compatible ``/chat/completions`` adapter.

    Implemented lazily via :mod:`urllib` to avoid pulling in a heavier
    HTTP client. The caller is responsible for JSON-schema validating
    the parsed response.
    """

    __slots__ = ("_api_key",)

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("VULN_INTEL_LLM_API_KEY", "")

    def chat(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float,
        base_url: str = "https://api.openai.com/v1",
    ) -> dict[str, Any]:
        import urllib.error
        import urllib.request

        url = f"{base_url.rstrip('/')}/chat/completions"
        body = json.dumps(
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.0,
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                raw = resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise LlmTransportError(str(exc)) from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:  # pragma: no cover — provider bug
            raise LlmTransportError(f"non-JSON response: {exc}") from exc


class FakeLlmClient:
    """In-process LLM client used by the test suite.

    The caller configures the next response via :attr:`next_response`
    (or :attr:`next_error` for a transport failure). When neither is
    set, the client returns a sane default response.
    """

    def __init__(self) -> None:
        self.next_response: dict[str, Any] | None = None
        self.next_error: Exception | None = None
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "model": model,
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.next_error is not None:
            err = self.next_error
            self.next_error = None
            raise err
        if self.next_response is not None:
            resp = self.next_response
            self.next_response = None
            return resp
        # Default: parse the cve_id out of the user prompt and return
        # a well-formed response with score 0.5.
        cve_id = "CVE-0000-0000"
        try:
            for line in user_prompt.splitlines():
                if line.startswith("CVE id: "):
                    cve_id = line.split(": ", 1)[1].strip()
                    break
        except Exception:  # pragma: no cover — defensive
            pass
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "cve_id": cve_id,
                                "exploit_likelihood": 0.5,
                                "rationale": "default test response",
                                "confidence": "medium",
                            }
                        )
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
            },
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------
class LlmExploitScorer:
    """Top-level scorer — call :meth:`score` to get an :class:`LlmScore`.

    Construction is cheap; reuse one instance per process. The
    underlying :class:`LlmClient` may be swapped (e.g. for tests) by
    reassigning the ``client`` attribute.
    """

    def __init__(
        self,
        config: LlmConfig,
        client: LlmClient | None = None,
    ) -> None:
        self._config = config
        self._client: LlmClient = client or HttpLlmClient()
        self._budget = _BudgetTracker()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def score(
        self,
        *,
        cve_id: str,
        cvss_vector: str,
        cvss_base_score: float,
        vendor: str,
        description: str,
        tenant_id: str = "default",
        # ``epss_score`` is consulted only when LLM is disabled or
        # falls back. It must be in [0.0, 1.0].
        epss_score: float | None = None,
    ) -> LlmScore:
        """Return an :class:`LlmScore` for the given CVE.

        Behaviour:

        * LLM disabled → returns :meth:`fallback_score` immediately.
        * LLM enabled but budget exhausted → returns fallback.
        * LLM enabled and budget available → calls the LLM, validates
          the response against :data:`LLM_RESPONSE_SCHEMA`, and emits
          an :class:`LlmCallAudit` event. On any failure, returns
          :meth:`fallback_score` and the audit row records the
          failure.
        """
        call_id = str(uuid.uuid4())

        if not self._config.enabled:
            self._audit(
                LlmCallAudit(
                    call_id=call_id,
                    tenant_id=tenant_id,
                    cve_id=cve_id,
                    model=self._config.model,
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    duration_ms=0,
                    status="disabled",
                    fallback_used=True,
                )
            )
            return self.fallback_score(cve_id, epss_score, call_id=call_id)

        user_prompt = USER_PROMPT_TEMPLATE.format(
            cve_id=cve_id,
            cvss_vector=cvss_vector or "UNKNOWN",
            cvss_base_score=float(cvss_base_score or 0.0),
            vendor=vendor or "UNKNOWN",
            description=(description or "")[:600],
        )
        # Approximate token count: 1 token ≈ 4 chars. We reserve both
        # prompt and an expected completion headroom.
        est_tokens = max(1, (len(user_prompt) + len(SYSTEM_PROMPT)) // 4 + 64)
        if not self._budget.try_consume(
            tenant_id,
            est_tokens,
            ceiling={
                "tenant": self._config.per_tenant_budget_tokens,
                "global": self._config.global_budget_tokens,
            },
        ):
            self._audit(
                LlmCallAudit(
                    call_id=call_id,
                    tenant_id=tenant_id,
                    cve_id=cve_id,
                    model=self._config.model,
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    duration_ms=0,
                    status="budget_exceeded",
                    fallback_used=True,
                )
            )
            return self.fallback_score(cve_id, epss_score, call_id=call_id)

        start = time.perf_counter()
        last_error: str | None = None
        response: dict[str, Any] | None = None
        for attempt in range(self._config.max_retries + 1):
            try:
                response = self._client.chat(
                    model=self._config.model,
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    timeout_seconds=self._config.timeout_seconds,
                )
                last_error = None
                break
            except LlmTransportError as exc:
                last_error = str(exc)
                logger.warning(
                    "llm_transport_error attempt=%s error=%s cve_id=%s",
                    attempt, last_error, cve_id,
                )
                # Refund the reservation so a transient failure does
                # not consume the budget.
                self._budget.refund(tenant_id, est_tokens)
                if attempt < self._config.max_retries:
                    time.sleep(0.2 * (2**attempt))
                    # Re-reserve for the next attempt.
                    if not self._budget.try_consume(
                        tenant_id,
                        est_tokens,
                        ceiling={
                            "tenant": self._config.per_tenant_budget_tokens,
                            "global": self._config.global_budget_tokens,
                        },
                    ):
                        break

        duration_ms = int((time.perf_counter() - start) * 1000)
        if response is None:
            self._audit(
                LlmCallAudit(
                    call_id=call_id,
                    tenant_id=tenant_id,
                    cve_id=cve_id,
                    model=self._config.model,
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=est_tokens,
                    duration_ms=duration_ms,
                    status="transport_error",
                    error=last_error,
                    fallback_used=True,
                )
            )
            return self.fallback_score(cve_id, epss_score, call_id=call_id)

        parsed = self._parse_response(response, cve_id)
        usage = response.get("usage", {}) or {}
        prompt_tokens = int(usage.get("prompt_tokens", 0))
        completion_tokens = int(usage.get("completion_tokens", 0))
        total_tokens = int(usage.get("total_tokens", prompt_tokens + completion_tokens))
        if parsed is None:
            self._audit(
                LlmCallAudit(
                    call_id=call_id,
                    tenant_id=tenant_id,
                    cve_id=cve_id,
                    model=self._config.model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    duration_ms=duration_ms,
                    status="schema_violation",
                    error="LLM response did not match LLM_RESPONSE_SCHEMA",
                    fallback_used=True,
                )
            )
            return self.fallback_score(cve_id, epss_score, call_id=call_id)

        # Adjust the budget using the *actual* token usage reported by
        # the provider (best effort). Any over-reservation is refunded.
        actual = max(total_tokens, 1)
        if actual < est_tokens:
            self._budget.refund(tenant_id, est_tokens - actual)
        elif actual > est_tokens:
            # Provider reports more usage than we estimated. The
            # reservation was already accepted, so we just log the
            # delta and continue.
            logger.info(
                "llm_usage_above_estimate cve_id=%s reserved=%s actual=%s",
                cve_id, est_tokens, actual,
            )

        self._audit(
            LlmCallAudit(
                call_id=call_id,
                tenant_id=tenant_id,
                cve_id=cve_id,
                model=self._config.model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                duration_ms=duration_ms,
                status="ok",
            )
        )
        return LlmScore(
            cve_id=cve_id,
            score=float(parsed["exploit_likelihood"]),
            confidence=str(parsed["confidence"]),
            rationale=str(parsed["rationale"]),
            source="llm",
            used_tokens=total_tokens,
            call_id=call_id,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def fallback_score(
        self,
        cve_id: str,
        epss_score: float | None,
        *,
        call_id: str = "",
    ) -> LlmScore:
        """Return an EPSS-backed fallback :class:`LlmScore`."""
        if epss_score is None:
            score = 0.0
        else:
            score = max(0.0, min(1.0, float(epss_score)))
        return LlmScore(
            cve_id=cve_id,
            score=score,
            confidence="low",
            rationale="LLM scoring unavailable — using EPSS fallback.",
            source="epss_fallback",
            used_tokens=0,
            call_id=call_id or str(uuid.uuid4()),
        )

    def _parse_response(
        self, response: dict[str, Any], cve_id: str
    ) -> dict[str, Any] | None:
        """Extract + validate the JSON body of the LLM response."""
        try:
            choices = response["choices"]
            content = choices[0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None
        if not isinstance(content, str):
            return None
        try:
            body = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(body, dict):
            return None
        # Reject the response if the model "hallucinated" a different
        # CVE id than the one we asked about.
        if body.get("cve_id") and body["cve_id"] != cve_id:
            return None
        errors = sorted(_llm_response_validator.iter_errors(body), key=lambda e: e.path)
        if errors:
            return None
        return body

    def _audit(self, event: LlmCallAudit) -> None:
        # Always log to the structured logger so audit events are
        # captured by the platform's log shipper. The per-tenant
        # budget is reported alongside for capacity planning.
        logger.info(
            "llm_audit call_id=%s tenant_id=%s cve_id=%s model=%s "
            "prompt_tokens=%s completion_tokens=%s total_tokens=%s "
            "duration_ms=%s status=%s error=%s fallback_used=%s timestamp=%s",
            event.call_id,
            event.tenant_id,
            event.cve_id,
            event.model,
            event.prompt_tokens,
            event.completion_tokens,
            event.total_tokens,
            event.duration_ms,
            event.status,
            event.error,
            event.fallback_used,
            event.timestamp,
        )


# ---------------------------------------------------------------------------
# Bulk helper for the ingest pipeline
# ---------------------------------------------------------------------------
def score_batch(
    scorer: LlmExploitScorer,
    items: Iterable[dict[str, Any]],
    *,
    tenant_id: str = "default",
) -> list[LlmScore]:
    """Score a batch of CVEs sequentially.

    Each ``item`` must provide ``cve_id``, ``cvss_vector``,
    ``cvss_base_score``, ``vendor``, ``description``, and
    ``epss_score``.
    """
    out: list[LlmScore] = []
    for item in items:
        out.append(
            scorer.score(
                cve_id=item["cve_id"],
                cvss_vector=item.get("cvss_vector", ""),
                cvss_base_score=float(item.get("cvss_base_score", 0.0)),
                vendor=item.get("vendor", ""),
                description=item.get("description", ""),
                tenant_id=tenant_id,
                epss_score=item.get("epss_score"),
            )
        )
    return out
