"""
Unit tests for the security.ssrf module.

Covers:
  - IP literal classification (RFC 1918, loopback, link-local, multicast,
    reserved, IPv6 ULA/link-local/loopback/multicast, IPv4-mapped)
  - Hostname classification (banned suffixes, bare banned hostnames)
  - Allowlist matching (exact, wildcard, case-insensitive)
  - Async resolution + DNS-rebinding detection (mocked)
  - Top-level `assert_safe_target` happy path and rejection paths
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import pytest

from sbom_generator.security.ssrf import (
    ResolvedHost,
    SsrfCheckResult,
    assert_safe_target,
    classify_hostname,
    extract_host,
    host_matches_allowlist,
    is_private_ip,
    parse_image_reference,
    resolve_and_check,
)


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        # RFC 1918
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.255.254",
        # Loopback
        "127.0.0.1",
        "127.255.255.254",
        # Link-local / cloud metadata
        "169.254.0.1",
        "169.254.169.254",
        # Multicast
        "224.0.0.1",
        "239.255.255.255",
        # CGNAT
        "100.64.0.1",
        # Reserved
        "0.0.0.0",
        "240.0.0.1",
        "255.255.255.255",
        # TEST-NET
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        # IPv6
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff00::1",
        "2001:db8::1",
        "::ffff:10.0.0.1",  # IPv4-mapped
    ],
)
def test_is_private_ip_blocks_reserved(ip):
    assert is_private_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",                 # Google DNS
        "1.1.1.1",                 # Cloudflare DNS
        "93.184.216.34",           # example.com
        "2606:4700:4700::1111",    # Cloudflare DNS v6
    ],
)
def test_is_private_ip_allows_public(ip):
    assert is_private_ip(ip) is False


def test_is_private_ip_invalid_input_fails_closed():
    """Invalid IP strings are treated as private (fail-closed)."""
    assert is_private_ip("not-an-ip") is True
    assert is_private_ip("") is True
    assert is_private_ip("999.999.999.999") is True


# ---------------------------------------------------------------------------
# classify_hostname
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "api.localhost",
        "api.internal",
        "api.intranet",
        "api.corp",
        "api.lan",
        "metadata.google.internal",
    ],
)
def test_classify_hostname_blocks_banned(host):
    reason = classify_hostname(host)
    assert reason is not None
    assert "banned" in reason or "private" in reason


@pytest.mark.parametrize(
    "host,ip",
    [
        ("10.0.0.1", "10.0.0.1"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("169.254.169.254", "169.254.169.254"),
    ],
)
def test_classify_hostname_blocks_ip_literals(host, ip):
    reason = classify_hostname(host)
    assert reason is not None
    assert ip in reason


@pytest.mark.parametrize(
    "host",
    [
        "github.com",
        "gitlab.com",
        "example.com",
        "8.8.8.8",
        "1.1.1.1",
    ],
)
def test_classify_hostname_allows_public(host):
    assert classify_hostname(host) is None


def test_classify_hostname_empty_fails_closed():
    assert classify_hostname("") is not None
    assert classify_hostname("   ") is not None


# ---------------------------------------------------------------------------
# extract_host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/o/r", "github.com"),
        ("https://github.com:443/o/r", "github.com"),
        ("http://10.0.0.1/x", "10.0.0.1"),
        ("https://[::1]:5000/v2/", "::1"),
        ("git@github.com:o/r.git", "github.com"),  # bare scp-style without scheme
        ("github.com", "github.com"),
        ("localhost:5000", "localhost"),
        # MAJOR fix: user@ must be stripped BEFORE bracket handling, else
        # a bracketed IPv6 literal with userinfo is never bracket-parsed.
        ("attacker@10.0.0.1:22/x", "10.0.0.1"),
        ("user@[::1]:22/x", "::1"),
        ("https://u:p@10.0.0.1/x", "10.0.0.1"),
    ],
)
def test_extract_host(url, expected):
    assert extract_host(url) == expected


# ---------------------------------------------------------------------------
# host_matches_allowlist
# ---------------------------------------------------------------------------


def test_allowlist_exact_match():
    assert host_matches_allowlist("github.com", ["github.com"]) is True


def test_allowlist_case_insensitive():
    assert host_matches_allowlist("GitHub.com", ["github.com"]) is True
    assert host_matches_allowlist("GITHUB.COM", ["github.com"]) is True


def test_allowlist_wildcard_subdomain():
    allowlist = ["*.github.com"]
    assert host_matches_allowlist("api.github.com", allowlist) is True
    assert host_matches_allowlist("github.com", allowlist) is False  # bare not matched by wildcard


def test_allowlist_multiple_entries():
    allowlist = ["github.com", "*.github.com", "gitlab.com"]
    assert host_matches_allowlist("api.github.com", allowlist) is True
    assert host_matches_allowlist("gitlab.com", allowlist) is True
    assert host_matches_allowlist("bitbucket.org", allowlist) is False


def test_allowlist_empty():
    assert host_matches_allowlist("github.com", []) is False
    assert host_matches_allowlist("", ["github.com"]) is False


# ---------------------------------------------------------------------------
# resolve_and_check (async, mocked)
# ---------------------------------------------------------------------------


def _mock_addrinfo(addresses):
    """Build a fake addrinfo return value (list of 5-tuples)."""
    infos = []
    for addr in addresses:
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        sockaddr = (addr, 0) if family == socket.AF_INET else (addr, 0, 0, 0)
        infos.append((family, socket.SOCK_STREAM, 0, "", sockaddr))
    return infos


def test_resolve_and_check_all_public():
    async def run():
        with patch(
            "asyncio.base_events.BaseEventLoop.getaddrinfo",
            new=AsyncMock(return_value=_mock_addrinfo(["8.8.8.8", "1.1.1.1"])),
        ):
            return await resolve_and_check("github.com")
    res = asyncio.run(run())
    assert res.ok
    assert "8.8.8.8" in res.addresses
    assert "1.1.1.1" in res.addresses


def test_resolve_and_check_dns_rebinding_to_private():
    """A hostname that resolves to a private IP is blocked."""
    async def run():
        with patch(
            "asyncio.base_events.BaseEventLoop.getaddrinfo",
            new=AsyncMock(return_value=_mock_addrinfo(["10.0.0.5"])),
        ):
            return await resolve_and_check("attacker.example.com")
    res = asyncio.run(run())
    assert not res.ok
    assert "rebind" in (res.blocked_reason or "").lower()
    assert "10.0.0.5" in (res.blocked_reason or "")


def test_resolve_and_check_timeout_fails_closed():
    """A DNS resolution timeout must fail closed."""
    async def run():
        with patch(
            "asyncio.base_events.BaseEventLoop.getaddrinfo",
            new=AsyncMock(side_effect=asyncio.TimeoutError),
        ):
            with pytest.raises(asyncio.TimeoutError):
                await resolve_and_check("slow.example.com", timeout_seconds=0.01)
    asyncio.run(run())


# ---------------------------------------------------------------------------
# assert_safe_target (top-level)
# ---------------------------------------------------------------------------


def test_assert_safe_target_rejects_ip_literal():
    async def run():
        return await assert_safe_target(
            "https://10.0.0.1/repo.git",
            allowlist=("github.com",),
            default_deny=True,
        )
    res = asyncio.run(run())
    assert res.allowed is False
    assert "private" in res.reason or "reserved" in res.reason


def test_assert_safe_target_rejects_banned_hostname():
    async def run():
        return await assert_safe_target(
            "https://api.internal/repo.git",
            allowlist=("github.com",),
            default_deny=True,
        )
    res = asyncio.run(run())
    assert res.allowed is False


def test_assert_safe_target_default_deny_when_no_allowlist_match():
    async def run():
        return await assert_safe_target(
            "https://gitlab.internalcorp.com/o/r.git",
            allowlist=("github.com", "*.github.com"),
            default_deny=True,
        )
    res = asyncio.run(run())
    assert res.allowed is False
    assert "allowlist" in res.reason


def test_assert_safe_target_allows_allowlisted():
    async def run():
        with patch(
            "asyncio.base_events.BaseEventLoop.getaddrinfo",
            new=AsyncMock(return_value=_mock_addrinfo(["140.82.114.3"])),
        ):
            return await assert_safe_target(
                "https://github.com/aionrs/api.git",
                allowlist=("github.com", "*.github.com"),
                default_deny=True,
            )
    res = asyncio.run(run())
    assert res.allowed is True
    assert "140.82.114.3" in res.resolved_addresses


def test_assert_safe_target_dns_rebinding_caught():
    """Hostname that resolves to a private IP is blocked even if allowlisted."""
    async def run():
        with patch(
            "asyncio.base_events.BaseEventLoop.getaddrinfo",
            new=AsyncMock(return_value=_mock_addrinfo(["192.168.1.1"])),
        ):
            return await assert_safe_target(
                "https://github.com.attacker.com/o/r.git",
                allowlist=("github.com", "*.attacker.com"),
                default_deny=True,
            )
    res = asyncio.run(run())
    assert res.allowed is False
    assert "rebind" in res.reason.lower()
    assert "192.168.1.1" in res.resolved_addresses


# ---------------------------------------------------------------------------
# parse_image_reference (T-07 / S9-1: syft scheme-injection defense)
# ---------------------------------------------------------------------------
# These MUST fail on the pre-fix code (the old permissive regex
# ``^[a-z0-9./:_@\-]+$`` plus ``_extract_image_host``/``_docker_ref_host``),
# which let syft's own scheme parsing (independent of ``--source``) read
# local files or reach an internal registry.


@pytest.mark.parametrize(
    "value",
    [
        "registry:10.0.0.1:5000/x",
        "registry://10.0.0.1/x",
        "docker://x",
        "dir:/etc",
        "file:/etc/passwd",
        "oci-archive:/etc/shadow",
        "oci-dir:/tmp/x",
        "docker-archive:/x.tar",
        "DIR:/etc",
        "docker-daemon:x",
        "podman:x",
        "singularity:/x",
    ],
)
def test_parse_image_reference_rejects_scheme_injection(value):
    with pytest.raises(ValueError):
        parse_image_reference(value)


@pytest.mark.parametrize(
    "value,expected_host",
    [
        ("127.0.0.1/x", "127.0.0.1"),
        ("localhost:5000/x", "localhost"),
        ("10.0.0.1:5000/img", "10.0.0.1"),
        ("[::1]:5000/x", "::1"),
    ],
)
def test_parse_image_reference_extracts_host_for_ssrf_check(value, expected_host):
    """Not rejected by the grammar itself — the extracted host must then
    be classified by ``classify_hostname``/``assert_safe_target``, which
    blocks these as private/loopback."""
    host, _ = parse_image_reference(value)
    assert host == expected_host
    assert classify_hostname(host) is not None


def test_parse_image_reference_rejects_not_allowlisted_host_via_classify():
    """``evil-registry.io`` isn't private, so the grammar/blocklist layer
    accepts it — the registry allow-list (agent.py) is what rejects it."""
    host, remainder = parse_image_reference("evil-registry.io/x")
    assert host == "evil-registry.io"
    assert remainder == "x"
    assert classify_hostname(host) is None  # not on the blocklist


@pytest.mark.parametrize(
    "value,expected_host,expected_remainder",
    [
        ("nginx", None, "nginx"),
        ("nginx:1.25", None, "nginx:1.25"),
        ("library/nginx:1.25", None, "library/nginx:1.25"),
        ("internal-namespace/img", None, "internal-namespace/img"),
        ("docker.io/library/nginx:1.25", "docker.io", "library/nginx:1.25"),
        (
            "ghcr.io/org/app@sha256:" + "a" * 64,
            "ghcr.io",
            "org/app@sha256:" + "a" * 64,
        ),
        ("quay.io/org/app:v1", "quay.io", "org/app:v1"),
    ],
)
def test_parse_image_reference_accepts_valid_refs(value, expected_host, expected_remainder):
    host, remainder = parse_image_reference(value)
    assert host == expected_host
    assert remainder == expected_remainder
