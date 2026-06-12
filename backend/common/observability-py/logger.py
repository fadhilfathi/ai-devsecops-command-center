# =============================================================================
# Structured logger — Python reference (Sprint 2)
# Owner: SREEngineer
# See: docs/observability/monitoring-architecture.md §5
#       infra/observability/logs/log-schema.json
#
# Mirror of backend/common/observability/logger.ts.
#
# structlog with:
#   - W3C trace context propagation (trace_id, span_id)
#   - PII redaction at the SDK boundary
#   - Mandatory fields: timestamp, level, service, version, env, tenant_id,
#     trace_id, span_id, agent_id (if present), event, message
#   - JSON schema validation in dev/test; off in prod
# =============================================================================

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import os
import re
import sys
from typing import Any, Literal

import structlog
from opentelemetry import trace as _otel_trace

# ---------------------------------------------------------------------------
# Re-redaction (mirrors the TypeScript set; keep in sync)
# ---------------------------------------------------------------------------
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE), "email"),
    (re.compile(r"(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}"), "phone"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "bearer"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "jwt"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "private_key",
    ),
]

# Secret keys (dict keys) whose value is always redacted wholesale.
_SECRET_KEYS: frozenset[str] = frozenset(
    {"authorization", "cookie", "password", "secret", "token", "api_key", "apikey"}
)

# Component names can leak org info — a Sprint 2 requirement from the Lead.
# Redact everything except the ecosystem prefix and the top-level package name.
_COMPONENT_NAME_REDACT: re.Pattern[str] = re.compile(
    r"^(?P<ecos>[a-z0-9+.\-]+)/(?P<name>[a-z0-9.\-]+)(?P<rest>.*)$"
)


def _redact_string(value: str) -> str:
    out = value
    for pattern, label in _REDACT_PATTERNS:
        out = pattern.sub(f"[REDACTED:{label}]", out)
    return out


def _redact_component_name(name: str) -> str:
    """Mask internal org/team info embedded in package coordinates."""
    m = _COMPONENT_NAME_REDACT.match(name)
    if not m:
        return "[REDACTED:component]"
    return f"{m.group('ecos')}/{m.group('name')}/[REDACTED:scope]"


def _stable_hash(value: str) -> str:
    """HMAC-SHA256 of a value with a rotating key — for cardinality preservation."""
    key_env = os.getenv("LOG_HASH_KEY", "sre-default-key-rotate-me")
    return hmac.new(
        key_env.encode("utf-8"), value.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _redact_value(value: Any, *, in_production: bool) -> Any:
    if isinstance(value, str):
        out = _redact_string(value)
        if in_production:
            # In production, component names get the org mask applied too.
            if "/" in out and " " not in out and len(out) < 256:
                # Heuristic: only mask things that look like package coordinates.
                if re.fullmatch(r"[A-Za-z0-9+_./\-:@]+", out):
                    out = _redact_component_name(out)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact_value(v, in_production=in_production) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k.lower() in _SECRET_KEYS:
                out[k] = "[REDACTED:secret]"
            else:
                out[k] = _redact_value(v, in_production=in_production)
        return out
    return value


# ---------------------------------------------------------------------------
# Trace context injection
# ---------------------------------------------------------------------------
def _inject_trace_context(event_dict: dict[str, Any]) -> dict[str, Any]:
    span = _otel_trace.get_current_span()
    if span is None:
        return event_dict
    ctx = span.get_span_context()
    if not ctx or not ctx.is_valid:
        return event_dict
    if ctx.trace_id:
        event_dict.setdefault("trace_id", format(ctx.trace_id, "032x"))
    if ctx.span_id:
        event_dict.setdefault("span_id", format(ctx.span_id, "016x"))
    return event_dict


# ---------------------------------------------------------------------------
# JSON schema validation (dev/test only)
# ---------------------------------------------------------------------------
def _maybe_validate_schema(event_dict: dict[str, Any], env: str) -> None:
    if env == "prod":
        return
    required = {"timestamp", "level", "service", "version", "env", "tenant_id", "event", "message"}
    missing = required - event_dict.keys()
    if missing:
        sys.stderr.write(
            f"[log-validator] missing required fields: {sorted(missing)}\n"
        )


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------
LogLevel = Literal["debug", "info", "warn", "error", "fatal"]


def create_logger(
    service: str,
    version: str,
    env: Literal["dev", "staging", "prod"] = "dev",
    agent_id: str | None = None,
    level: LogLevel | None = None,
) -> structlog.stdlib.BoundLogger:
    """
    Build a structlog logger bound to the standard SRE fields. Returns a
    `BoundLogger` you can call with kwargs that get merged into the JSON
    payload as `context`.
    """
    if not re.match(r"^[a-z][a-z0-9-]{1,63}$", service):
        raise ValueError(f"Invalid service name: {service!r}")
    if env not in ("dev", "staging", "prod"):
        raise ValueError(f"Invalid env: {env!r}")

    in_production = env == "prod"
    chosen_level = level or ("info" if env == "prod" else "debug")

    def _add_timestamp(_, __, event_dict):
        event_dict.setdefault(
            "timestamp",
            _dt.datetime.now(tz=_dt.timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        )
        return event_dict

    def _add_service_metadata(_, __, event_dict):
        event_dict.setdefault("service", service)
        event_dict.setdefault("version", version)
        event_dict.setdefault("env", env)
        if agent_id is not None:
            event_dict.setdefault("agent_id", agent_id)
        if "tenant_id" not in event_dict:
            # Default to env var; required in prod, dev gets "unknown" for visibility.
            tid = os.getenv("TENANT_ID")
            event_dict["tenant_id"] = tid or ("unknown" if env == "dev" else "")
        return event_dict

    def _redact(_, __, event_dict):
        for k, v in list(event_dict.items()):
            if k in (
                "timestamp",
                "level",
                "service",
                "version",
                "env",
                "agent_id",
                "tenant_id",
                "trace_id",
                "span_id",
                "event",
                "message",
            ):
                continue
            event_dict[k] = _redact_value(v, in_production=in_production)
        return event_dict

    def _validate(_, __, event_dict):
        _maybe_validate_schema(event_dict, env)
        return event_dict

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _add_service_metadata,
            _add_timestamp,
            _inject_trace_context,
            _redact,
            _validate,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            _level_value(chosen_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger()


def _level_value(level: LogLevel) -> int:
    return {
        "debug": 10,
        "info": 20,
        "warn": 30,
        "error": 40,
        "fatal": 50,
    }[level]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def with_tenant(logger, tenant_id: str):
    return logger.bind(tenant_id=tenant_id)


def with_user(logger, user_id: str):
    """Bind a *hashed* user_id; never pass plaintext identifiers."""
    return logger.bind(user_id=_stable_hash(user_id))
