"""Request schemas for the SBOM generator HTTP service.

The request model is intentionally a superset of all source kinds so
that callers don't have to learn a per-source type. The source kind
itself is encoded in the ``source.type`` field.

T-07 SSRF defense (S2.8 hotfix):
  - The synchronous validator at module level classifies the target host
    against the CIDR/hostname blocklist in `security.ssrf`. IP literals
    that fall in private/reserved ranges are rejected at the model layer
    so they never reach the service code.
  - The asynchronous DNS-rebinding check lives in the service layer
    (see ``SbomService.generate``). The model layer is sync-only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from sbom_generator.errors import SsrfBlockedError, ValidationError
from sbom_generator.models.sbom import SBOMFormat
from sbom_generator.security.ssrf import classify_hostname, extract_host


class SourceType(str):
    """String enum of supported source kinds."""

    DIRECTORY = "directory"
    FILE = "file"
    DOCKER_IMAGE = "docker-image"
    OCI_IMAGE = "oci-image"
    GIT_REPOSITORY = "git-repository"
    ARCHIVE = "archive"
    REGISTRY = "registry"


VALID_SOURCE_TYPES = {
    SourceType.DIRECTORY,
    SourceType.FILE,
    SourceType.DOCKER_IMAGE,
    SourceType.OCI_IMAGE,
    SourceType.GIT_REPOSITORY,
    SourceType.ARCHIVE,
    SourceType.REGISTRY,
}


class SourceRef(BaseModel):
    """A reference to the artifact to scan.

    ``type`` discriminates the kind. ``value`` carries the actual
    location (path, image reference, git URL, …). ``options`` allow
    call-site specific overrides (e.g. ``tag`` or ``digest`` for
    images, ``ref`` for git, …).
    """

    type: str
    value: str
    options: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        if v not in VALID_SOURCE_TYPES:
            raise ValueError(
                f"unsupported source.type={v!r}. valid: "
                f"{sorted(VALID_SOURCE_TYPES)}"
            )
        return v

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("source.value must not be empty")
        return v.strip()


class GenerateRequest(BaseModel):
    """The public request payload accepted by ``POST /v1/sbom/generate``."""

    source: SourceRef
    formats: List[SBOMFormat] = Field(
        default_factory=lambda: [SBOMFormat.CYCLONEDX_JSON]
    )
    scan_root: Optional[str] = None
    exclude_paths: List[str] = Field(default_factory=list)
    include_dev_dependencies: bool = False
    catalogs: Optional[List[str]] = None
    output_relationships: bool = True
    metadata: Dict[str, str] = Field(default_factory=dict)
    tenant_id: Optional[str] = None

    @field_validator("formats")
    @classmethod
    def _validate_formats(cls, v: List[SBOMFormat]) -> List[SBOMFormat]:
        if not v:
            raise ValueError("at least one format is required")
        return v

    def validate_source(self) -> None:
        """Cross-field checks that pydantic can't express declaratively.

        T-07 (S2.8 hotfix): for every source kind whose target is a remote
        resource, classify the host against the SSRF blocklist and reject
        private/reserved IP literals and banned hostnames. The async
        DNS-rebinding check (host resolves to private IP) is enforced at
        the service layer before the Syft subprocess runs.
        """
        kind = self.source.type
        target = self.source.value
        if kind in {SourceType.DIRECTORY, SourceType.FILE, SourceType.ARCHIVE}:
            # Local path; do not require URL parsing but reject obvious
            # URL characters to avoid confusion.
            if "://" in target and not target.startswith("file://"):
                raise ValidationError(
                    "Local path sources must not include a URL scheme",
                    details={"source": self.source.model_dump()},
                )
        elif kind in {SourceType.DOCKER_IMAGE, SourceType.OCI_IMAGE}:
            if not re.match(r"^[a-z0-9./:_@\-]+$", target):
                raise ValidationError(
                    "Invalid image reference", details={"value": target}
                )
            # SSRF: reject image references pointing at private/loopback hosts.
            # docker.io/library/foo is fine; 10.0.0.5:5000/foo is not.
            image_host = self._extract_image_host(target)
            if image_host is not None:
                self._assert_host_ssrf_safe(image_host, target)
        elif kind == SourceType.GIT_REPOSITORY:
            parsed = urlparse(target)
            # Accept three SSH-like forms:
            # 1. ``ssh://[user@]host[:port]/path``  (explicit scheme)
            # 2. ``[user@]host:path``              (scp-style, GitHub's default)
            # 3. ``git://host/path``               (the git protocol)
            if parsed.scheme in {"https", "git", "ssh", "file"}:
                pass  # explicit URL scheme is fine
            elif re.match(r"^[\w-]+@[\w.-]+:.+$", target):
                # SCP-style: ``git@github.com:owner/repo.git``
                pass
            else:
                raise ValidationError(
                    "git-repository source requires https/git/ssh/file scheme "
                    "or scp-style [user@]host:path form",
                    details={"value": target, "scheme": parsed.scheme or None},
                )
            # SSRF: classify the host portion against the blocklist.
            git_host = self._extract_git_host(target)
            if git_host is not None:
                self._assert_host_ssrf_safe(git_host, target)
        elif kind == SourceType.REGISTRY:
            parsed = urlparse(target)
            if parsed.scheme not in {"https", "http"}:
                raise ValidationError(
                    "registry source requires http(s) URL",
                    details={"value": target},
                )
            # SSRF: classify the URL host against the blocklist.
            if parsed.hostname:
                self._assert_host_ssrf_safe(parsed.hostname, target)

    @staticmethod
    def _extract_git_host(target: str) -> Optional[str]:
        """Extract the host portion of a git URL or scp-style form."""
        parsed = urlparse(target)
        if parsed.hostname:
            return parsed.hostname
        # scp-style: ``user@host:path``
        m = re.match(r"^[\w-]+@([\w.\-]+):", target)
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _extract_image_host(reference: str) -> Optional[str]:
        """Extract the registry host from an OCI image reference.

        Examples:
          ``docker.io/library/alpine`` -> ``docker.io``
          ``ghcr.io/owner/repo:tag``   -> ``ghcr.io``
          ``10.0.0.5:5000/repo``       -> ``10.0.0.5``
          ``[::1]:5000/repo``          -> ``::1``
          ``alpine``                   -> ``docker.io`` (Docker Hub default)
        """
        # Split off the tag/digest first.
        ref = reference.split("@", 1)[0]
        # The first component (before the first '/') is the registry.
        # If it contains '.' or ':' or is 'localhost', it is a registry;
        # otherwise it's a Docker Hub library path and the implicit
        # registry is docker.io.
        first_slash = ref.find("/")
        if first_slash == -1:
            # bare name like ``alpine`` -> default registry
            return "docker.io"
        first = ref[:first_slash]
        if (
            first == "localhost"
            or first == "localhost:"
            or ":" in first
            or (first.startswith("[") and first.endswith("]"))
            or "." in first
        ):
            # IPv6 literal: ``[::1]``
            if first.startswith("[") and first.endswith("]"):
                return first[1:-1]
            # Strip an embedded port: ``10.0.0.5:5000`` -> ``10.0.0.5``
            if ":" in first and not first.startswith("["):
                # Could be either host:port or just host. If second segment
                # after the colon is all digits, treat as port.
                host, _, port = first.partition(":")
                if port.isdigit():
                    return host
                return first
            return first
        # No registry component -> Docker Hub default.
        return "docker.io"

    @staticmethod
    def _assert_host_ssrf_safe(host: str, target: str) -> None:
        """Reject `host` if it is on the SSRF blocklist.

        Raises ``SsrfBlockedError`` (HTTP 400, code ``ssrf_blocked``) so the
        service layer can surface a precise error code to the caller.
        """
        if not host:
            return
        reason = classify_hostname(host)
        if reason is not None:
            raise SsrfBlockedError(
                f"SSRF defense: target host rejected ({reason})",
                details={"value": target, "host": host, "reason": reason},
            )
