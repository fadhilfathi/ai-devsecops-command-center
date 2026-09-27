"""
SSRF (Server-Side Request Forgery) defense for dev_input targets.

T-07 mitigation in S2.8 hardening hotfix. Two layers:

  1. **Synchronous** (Pydantic validator): classify the URL host against a
     CIDR/hostname blocklist. Reject if the host is a private/reserved IP
     literal or a banned hostname suffix.

  2. **Asynchronous** (service layer, before Syft subprocess): resolve
     hostnames via `getaddrinfo`, then classify every returned address
     against the SAME blocklist. This catches DNS-rebinding attacks where
     a hostname resolves to a private IP at request time.

The two layers use the same blocklist and classification primitives so the
rules stay in lockstep.

The blocklist is deliberately conservative — it is the "what we *never*
want to fetch" set. The allowlist (configured by the operator) is the
"what we *do* want to fetch" set. When the allowlist is non-empty and the
host is not in the allowlist, the request is rejected (default-deny).

Spec owner: SecurityArchitect (slot 019ebae2-9de4-7223-9920-60866bc88d45).
Locked: 2026-06-12.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Blocklist definitions
# ---------------------------------------------------------------------------

# IPv4 CIDRs that must never be the target of an outbound fetch. Sourced from
# RFC 1918, RFC 6890, RFC 5735, RFC 6890, and the cloud-metadata addresses.
# Reference: IANA IPv4 Special-Purpose Address Registry.
_BLOCKED_IPV4_CIDRS: Sequence[str] = (
    # Private use (RFC 1918)
    "0.0.0.0/8",        # "this network"
    "10.0.0.0/8",       # private
    "100.64.0.0/10",    # CGNAT (RFC 6598)
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local (incl. cloud metadata 169.254.169.254)
    "172.16.0.0/12",    # private
    "192.0.0.0/24",     # IETF protocol assignments
    "192.0.2.0/24",     # TEST-NET-1 (RFC 5737)
    "192.168.0.0/16",   # private
    "198.18.0.0/15",    # benchmarking (RFC 2544)
    "198.51.100.0/24",  # TEST-NET-2 (RFC 5737)
    "203.0.113.0/24",   # TEST-NET-3 (RFC 5737)
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved
    "255.255.255.255/32",  # broadcast
)

# IPv6 CIDRs that must never be the target of an outbound fetch.
_BLOCKED_IPV6_CIDRS: Sequence[str] = (
    "::/128",           # unspecified
    "::1/128",          # loopback
    "::ffff:0:0/96",    # IPv4-mapped (re-check embedded IPv4)
    "64:ff9b::/96",     # IPv4-IPv6 translation (RFC 6052)
    "100::/64",         # discard (RFC 6666)
    "2001::/23",        # IETF protocol assignments
    "2001:db8::/32",    # documentation (RFC 3849)
    "fc00::/7",         # unique local (ULA)
    "fe80::/10",        # link-local
    "ff00::/8",         # multicast
)

# Hostname suffixes that must never be the target. These are common in
# enterprise networks and would bypass IP-based blocklists.
_BLOCKED_HOSTNAME_SUFFIXES: Sequence[str] = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".corp",
    ".lan",
    ".home",
    ".private",
    ".test",
    ".invalid",
    ".example",
    ".example.com",
    ".example.net",
    ".example.org",
    # Cloud metadata hostnames (defense in depth — already covered by 169.254.0.0/16)
    "metadata.google.internal",
    "metadata.azure.com",
    "instance-data.ec2.internal",
)

# Bare hostnames (no dot) that must be rejected.
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset({
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
})


def _compile_blocklists() -> tuple[
    List[ipaddress.IPv4Network | ipaddress.IPv6Network],
    frozenset[str],
    frozenset[str],
]:
    """Compile CIDR blocklists once at import time.

    Returns (networks, suffix_set, bare_hostname_set).
    """
    nets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in _BLOCKED_IPV4_CIDRS:
        nets.append(ipaddress.ip_network(cidr, strict=False))
    for cidr in _BLOCKED_IPV6_CIDRS:
        nets.append(ipaddress.ip_network(cidr, strict=False))
    return (
        nets,
        frozenset(_BLOCKED_HOSTNAME_SUFFIXES),
        _BLOCKED_HOSTNAMES,
    )


_NETS, _SUFFIXES, _BARE_HOSTS = _compile_blocklists()


# ---------------------------------------------------------------------------
# Classification primitives
# ---------------------------------------------------------------------------

def is_private_ip(addr: str) -> bool:
    """Return True if `addr` is in any blocked CIDR.

    Accepts both IPv4 and IPv6 string forms. Returns True for invalid input
    (fail-closed).
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # fail-closed
    for net in _NETS:
        if isinstance(net, ipaddress.IPv4Network) and isinstance(ip, ipaddress.IPv4Address):
            if ip in net:
                return True
        elif isinstance(net, ipaddress.IPv6Network) and isinstance(ip, ipaddress.IPv6Address):
            if ip in net:
                return True
    return False


def classify_hostname(host: str) -> Optional[str]:
    """Return a reason string if the host is on the blocklist, else None.

    Checks (in order):
      1. Empty / whitespace
      2. Bare banned hostname (no dot)
      3. Banned hostname suffix
      4. IP literal in blocklist
    """
    h = host.strip().rstrip(".").lower()
    if not h:
        return "empty host"
    if h in _BARE_HOSTS:
        return f"banned hostname: {h}"
    for suffix in _SUFFIXES:
        bare = suffix.lstrip(".")
        if h.endswith(suffix):
            return f"banned hostname suffix: {suffix}"
        # Also block the bare, unqualified form (e.g. host "local" for
        # suffix ".local") — but only for single-label suffixes. Multi-
        # label suffixes like ".example.com" already cover subdomains via
        # endswith above; treating their bare form as banned too would
        # incorrectly block the exact public domain (e.g. "example.com"
        # itself, which is a real, routable RFC 2606 domain).
        if "." not in bare and h == bare:
            return f"banned hostname suffix: {suffix}"
    # IP literal?
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return None
    if is_private_ip(str(ip)):
        return f"private/reserved IP literal: {ip}"
    return None


def extract_host(url_or_host: str) -> str:
    """Return the host portion of a URL or pass through a bare hostname.

    Accepts ``https://github.com/o/r``, ``github.com:443``, ``[::1]``,
    and bare ``github.com`` forms.
    """
    s = url_or_host.strip()
    if "://" in s:
        parsed = urlparse(s)
        host = parsed.hostname or ""
        return host
    # scp-style "[user[:pass]@]host:path" (no scheme) — strip the
    # user@ prefix BEFORE the IPv6-bracket branch below. Doing this
    # after bracket handling (as a previous version of this function
    # did) meant "user@[::1]:22/x" was never bracket-parsed: the "["
    # check only looks at the very start of the string, and with the
    # "user@" prefix still attached the string starts with "u", not
    # "[", so the IPv6 literal slipped past classify_hostname
    # unclassified.
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    if s.startswith("["):
        # IPv6 literal, possibly with port
        end = s.find("]")
        if end != -1:
            return s[1:end]
    # Strip optional port
    if ":" in s and s.count(":") == 1:
        return s.split(":", 1)[0]
    return s


# ---------------------------------------------------------------------------
# Image-reference grammar (T-07 hardening: syft scheme-injection defense)
# ---------------------------------------------------------------------------
#
# ``syft`` interprets scheme prefixes (``registry:``, ``dir:``, ``file:``,
# ``oci-archive:``, ...) embedded in the *target string itself*,
# independent of any ``--source`` flag the caller passes on the CLI. A
# request like ``{"type": "docker-image", "value": "dir:/etc"}`` or
# ``"registry:10.0.0.1:5000/x"`` would therefore let an attacker read
# arbitrary local files or reach an internal registry even though the
# service always passes ``--source docker``/``--source oci`` — syft's own
# scheme parsing wins.
#
# ``parse_image_reference`` accepts *only* the plain OCI distribution
# reference grammar (no scheme of any kind) and returns the explicit
# registry host, if any. Both the model-layer validator
# (``models/request.py``) and the service layer (``agent.py``) call this
# single function so the two layers can never drift.

# Every scheme prefix syft's source-parsing recognizes. Checked
# case-insensitively against the start of the raw value. This list is
# defense-in-depth on top of the grammar check below (which already
# rejects any first path segment containing a ``:`` that isn't a valid
# ``host:port``) — it exists so an unambiguous, easily-audited reject
# reason is available for the common attack strings.
_SYFT_SCHEME_PREFIXES: Tuple[str, ...] = (
    "registry",
    "docker-daemon",
    "docker-archive",
    "docker",
    "oci-dir",
    "oci-archive",
    "podman",
    "singularity",
    "dir",
    "file",
)

_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_DNS_HOST = rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})+"  # requires >= 1 dot
_HOST_PORT_RE = re.compile(rf"^(?:{_DNS_HOST}|localhost)(?::[0-9]+)?$", re.IGNORECASE)
_IPV6_BRACKET_RE = re.compile(r"^\[(?P<addr>[0-9a-fA-F:]+)\](?::[0-9]+)?$")

_PATH_COMPONENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST = r"sha256:[0-9a-f]{64}"
_IMAGE_REMAINDER_RE = re.compile(
    rf"^{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*(?::{_TAG})?(?:@{_DIGEST})?$"
)


def parse_image_reference(value: str) -> Tuple[Optional[str], str]:
    """Parse a docker/oci image reference into ``(host, remainder)``.

    Accepts only the OCI distribution reference grammar:
    ``[registry-host[:port]/]path-component(/path-component)*[:tag][@sha256:<64hex>]``
    — no scheme of any kind. Raises :class:`ValueError` (with a
    human-readable reason) for anything else, including every known
    syft scheme prefix (``registry:``, ``dir:``, ``file:``, ...) and
    any first path segment that contains a ``:`` but isn't a valid
    ``host:port``.

    Returns ``(None, value)`` for bare references with no explicit
    registry host (e.g. ``nginx:1.25``, ``library/nginx`` — Docker Hub
    is the implicit default and is not attacker-controlled).
    """
    v = value.strip()
    if not v:
        raise ValueError("empty image reference")
    low = v.lower()
    if "://" in low:
        raise ValueError("image reference must not contain a URL scheme")
    for scheme in _SYFT_SCHEME_PREFIXES:
        if low.startswith(scheme + ":"):
            raise ValueError(
                f"image reference must not use the {scheme!r} scheme prefix"
            )

    first, sep, rest = v.partition("/")
    host: Optional[str] = None
    if sep:
        m6 = _IPV6_BRACKET_RE.match(first)
        if m6:
            host = m6.group("addr")
        elif _HOST_PORT_RE.match(first):
            host = first.split(":", 1)[0]
        elif ":" in first:
            raise ValueError(
                f"invalid registry host or scheme-like prefix: {first!r}"
            )
        remainder = rest if host is not None else v
    else:
        remainder = v

    if not remainder:
        raise ValueError("image reference is missing a path component")
    if not _IMAGE_REMAINDER_RE.match(remainder):
        raise ValueError(f"invalid image reference: {remainder!r}")
    return host, remainder


# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------

def host_matches_allowlist(host: str, allowlist: Iterable[str]) -> bool:
    """Return True if `host` matches any entry in the operator allowlist.

    Entries are exact hosts (``github.com``) or wildcard suffixes
    (``*.ghe.com``). Matching is case-insensitive.
    """
    h = host.strip().rstrip(".").lower()
    if not h:
        return False
    for raw in allowlist:
        entry = raw.strip().rstrip(".").lower()
        if not entry:
            continue
        if entry.startswith("*."):
            suffix = entry[1:]  # leading "." already part of entry
            if h.endswith(suffix) and h != suffix.lstrip("."):
                return True
        elif h == entry:
            return True
    return False


# ---------------------------------------------------------------------------
# Resolution + DNS-rebinding check
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolvedHost:
    """Result of resolving a hostname to one or more IPs."""
    hostname: str
    addresses: tuple[str, ...]
    # populated only when the resolution hits a blocked address
    blocked_reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.blocked_reason is None and len(self.addresses) > 0


async def resolve_and_check(
    host: str,
    *,
    timeout_seconds: float = 5.0,
) -> ResolvedHost:
    """Resolve `host` (async) and verify every returned IP.

    Raises asyncio.TimeoutError on DNS timeout (fail-closed: caller MUST
    treat a timeout as a block). Returns a ResolvedHost with
    ``blocked_reason`` set on any private/reserved address.
    """
    loop = asyncio.get_running_loop()
    # Run blocking getaddrinfo in the default thread pool.
    fut = loop.getaddrinfo(
        host,
        None,
        type=socket.SOCK_STREAM,
    )
    infos = await asyncio.wait_for(fut, timeout=timeout_seconds)
    addrs: List[str] = []
    blocked: Optional[str] = None
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        addrs.append(ip)
        if is_private_ip(ip) and blocked is None:
            blocked = (
                f"DNS rebinding: {host} resolves to private/reserved IP {ip}"
            )
    return ResolvedHost(
        hostname=host,
        addresses=tuple(addrs),
        blocked_reason=blocked,
    )


# ---------------------------------------------------------------------------
# Top-level check used by the service layer
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SsrfCheckResult:
    """Outcome of running the full SSRF defense on a dev_input target."""
    allowed: bool
    reason: str
    resolved_addresses: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.allowed


async def assert_safe_target(
    target: str,
    *,
    allowlist: Sequence[str],
    default_deny: bool,
    dns_timeout_seconds: float = 5.0,
) -> SsrfCheckResult:
    """Run the full SSRF defense on a dev_input URL/host.

    Order:
      1. Extract host from the URL
      2. Classify the host (sync): rejects IP literals and banned hostnames
      3. If allowlist is configured, enforce default-deny when no match
      4. Resolve hostname (async): rejects DNS rebinding to private IPs

    Returns a result describing whether the target is safe to fetch.
    The caller is responsible for raising on a non-allowed result.
    """
    host = extract_host(target)
    if not host:
        return SsrfCheckResult(allowed=False, reason="empty target host")

    # 1. Sync classification
    reason = classify_hostname(host)
    if reason is not None:
        return SsrfCheckResult(allowed=False, reason=reason)

    # 2. Allowlist default-deny
    if allowlist and not host_matches_allowlist(host, allowlist):
        return SsrfCheckResult(
            allowed=False,
            reason=f"host not in allowlist: {host}",
        )

    # 3. DNS rebinding check (only meaningful for hostnames, not literals)
    is_literal = False
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False

    if not is_literal:
        try:
            resolved = await resolve_and_check(
                host, timeout_seconds=dns_timeout_seconds
            )
        except asyncio.TimeoutError:
            return SsrfCheckResult(
                allowed=False,
                reason=f"DNS resolution timeout for {host} (fail-closed)",
            )
        except socket.gaierror as e:
            return SsrfCheckResult(
                allowed=False,
                reason=f"DNS resolution failed for {host}: {e}",
            )
        if not resolved.ok:
            return SsrfCheckResult(
                allowed=False,
                reason=resolved.blocked_reason or f"resolution failed for {host}",
                resolved_addresses=resolved.addresses,
            )
        return SsrfCheckResult(
            allowed=True,
            reason="ok",
            resolved_addresses=resolved.addresses,
        )

    # 4. IP literal path: nothing to resolve. Allowlist already enforced above.
    return SsrfCheckResult(allowed=True, reason="ip literal", resolved_addresses=(host,))


__all__ = [
    "SsrfCheckResult",
    "ResolvedHost",
    "assert_safe_target",
    "classify_hostname",
    "extract_host",
    "host_matches_allowlist",
    "is_private_ip",
    "parse_image_reference",
    "resolve_and_check",
]
