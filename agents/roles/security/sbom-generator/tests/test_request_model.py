"""Tests for the request model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from sbom_generator.errors import ValidationError
from sbom_generator.models.request import (
    GenerateRequest,
    SourceRef,
    SourceType,
    VALID_SOURCE_TYPES,
)
from sbom_generator.models.sbom import SBOMFormat


def test_source_ref_accepts_directory():
    s = SourceRef(type="directory", value=".")
    assert s.type == "directory"
    assert s.value == "."


def test_source_ref_strips_whitespace():
    s = SourceRef(type="directory", value="  /tmp  ")
    assert s.value == "/tmp"


def test_source_ref_rejects_empty_value():
    with pytest.raises(PydanticValidationError):
        SourceRef(type="directory", value="")


def test_source_ref_rejects_unknown_type():
    with pytest.raises(PydanticValidationError):
        SourceRef(type="crystal-ball", value="x")


def test_generate_request_default_format():
    req = GenerateRequest(source=SourceRef(type="directory", value="."))
    assert req.formats == [SBOMFormat.CYCLONEDX_JSON]


def test_generate_request_requires_one_format():
    with pytest.raises(PydanticValidationError):
        GenerateRequest(source=SourceRef(type="directory", value="."), formats=[])


def test_directory_source_rejects_url_scheme():
    req = GenerateRequest(
        source=SourceRef(type="directory", value="https://example.com/x")
    )
    with pytest.raises(ValidationError):
        req.validate_source()


def test_docker_image_rejects_bad_chars():
    req = GenerateRequest(
        source=SourceRef(type="docker-image", value="bad image ref!")
    )
    with pytest.raises(ValidationError):
        req.validate_source()


def test_git_source_requires_known_scheme():
    req = GenerateRequest(
        source=SourceRef(type="git-repository", value="ftp://example.com/repo")
    )
    with pytest.raises(ValidationError):
        req.validate_source()


def test_git_source_accepts_https():
    req = GenerateRequest(
        source=SourceRef(type="git-repository", value="https://github.com/a/b.git")
    )
    req.validate_source()  # no raise


def test_git_source_accepts_ssh():
    req = GenerateRequest(
        source=SourceRef(type="git-repository", value="git@github.com:a/b.git")
    )
    req.validate_source()


def test_registry_requires_http():
    req = GenerateRequest(
        source=SourceRef(type="registry", value="git://registry.example.com")
    )
    with pytest.raises(ValidationError):
        req.validate_source()


def test_oci_image_accepted():
    req = GenerateRequest(
        source=SourceRef(type="oci-image", value="ghcr.io/aionrs/api:v1.0.0")
    )
    req.validate_source()


def test_file_source_accepted():
    req = GenerateRequest(source=SourceRef(type="file", value="/tmp/Pipfile"))
    req.validate_source()


def test_archive_source_accepted():
    req = GenerateRequest(source=SourceRef(type="archive", value="/tmp/x.tar.gz"))
    req.validate_source()


def test_valid_source_types_includes_all_kinds():
    expected = {
        "directory",
        "file",
        "docker-image",
        "oci-image",
        "git-repository",
        "archive",
        "registry",
    }
    assert expected.issubset(VALID_SOURCE_TYPES)


# ---------------------------------------------------------------------------
# T-07 SSRF defense — SS-07a..SS-07j (S2.8 hotfix)
# ---------------------------------------------------------------------------
# These cases verify that the Pydantic-level SSRF defense rejects targets
# whose host is a private/reserved IP literal, a banned hostname, or fails
# the allowlist default-deny check. The async DNS-rebinding check is
# covered separately in tests/test_ssrf.py.
# ---------------------------------------------------------------------------


from sbom_generator.errors import SsrfBlockedError


@pytest.mark.parametrize(
    "value",
    [
        "https://10.0.0.1/repo.git",            # RFC 1918
        "https://10.255.255.254/repo.git",
        "https://172.16.0.1/repo.git",          # RFC 1918
        "https://172.31.255.254/repo.git",
        "https://192.168.0.1/repo.git",         # RFC 1918
        "https://192.168.1.254/repo.git",
    ],
)
def test_ss_07a_rfc1918_ipv4_blocked(value):
    """SS-07a: RFC 1918 IPv4 ranges in URL host are rejected."""
    req = GenerateRequest(source=SourceRef(type="git-repository", value=value))
    with pytest.raises(ValidationError) as exc_info:
        req.validate_source()
    # Must surface the SSRF code so the HTTP layer can render 400 cleanly.
    assert "ssrf" in str(exc_info.value).lower() or isinstance(
        exc_info.value, SsrfBlockedError
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://127.0.0.1/repo.git",           # loopback
        "https://127.255.255.254/repo.git",
        "https://0.0.0.0/repo.git",             # unspecified
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata
        "https://224.0.0.1/repo.git",           # multicast
        "https://255.255.255.255/repo.git",     # broadcast
    ],
)
def test_ss_07b_loopback_metadata_multicast_blocked(value):
    """SS-07b: loopback, metadata, multicast, broadcast ranges blocked."""
    req = GenerateRequest(source=SourceRef(type="git-repository", value=value))
    with pytest.raises(ValidationError) as exc_info:
        req.validate_source()
    assert "ssrf" in str(exc_info.value).lower() or isinstance(
        exc_info.value, SsrfBlockedError
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://[::1]/repo.git",               # IPv6 loopback
        "https://[fe80::1]/repo.git",           # IPv6 link-local
        "https://[fc00::1]/repo.git",           # IPv6 ULA
        "https://[ff00::1]/repo.git",           # IPv6 multicast
    ],
)
def test_ss_07c_ipv6_reserved_blocked(value):
    """SS-07c: IPv6 reserved ranges are rejected."""
    req = GenerateRequest(source=SourceRef(type="git-repository", value=value))
    with pytest.raises(ValidationError):
        req.validate_source()


def test_ss_07d_image_reference_private_registry_blocked():
    """SS-07d: docker-image references to private registries are rejected.

    ``10.0.0.5:5000/foo/bar`` would otherwise let an attacker direct Syft
    to a private registry. The image-host extractor must catch the bare
    IPv4 literal embedded in the reference.
    """
    req = GenerateRequest(
        source=SourceRef(type="docker-image", value="10.0.0.5:5000/foo/bar")
    )
    with pytest.raises(ValidationError) as exc_info:
        req.validate_source()
    assert "ssrf" in str(exc_info.value).lower() or isinstance(
        exc_info.value, SsrfBlockedError
    )


def test_ss_07e_registry_blocked_for_internal_host():
    """SS-07e: registry sources to private hosts are rejected."""
    req = GenerateRequest(
        source=SourceRef(type="registry", value="https://10.0.0.1/v2/")
    )
    with pytest.raises(ValidationError):
        req.validate_source()


def test_ss_07f_scp_style_internal_host_blocked():
    """SS-07f: SCP-style git URLs to private hosts are rejected."""
    req = GenerateRequest(
        source=SourceRef(
            type="git-repository", value="git@192.168.1.10:owner/repo.git"
        )
    )
    with pytest.raises(ValidationError):
        req.validate_source()


def test_ss_07g_banned_hostname_suffixes_blocked():
    """SS-07g: hostnames ending in banned suffixes are rejected."""
    for value in (
        "https://api.localhost/repo.git",
        "https://api.internal/repo.git",
        "https://api.intranet/repo.git",
        "https://api.corp/repo.git",
        "https://api.lan/repo.git",
        "https://metadata.google.internal/",
        "https://metadata.azure.com/",
    ):
        req = GenerateRequest(source=SourceRef(type="git-repository", value=value))
        with pytest.raises(ValidationError):
            req.validate_source()


def test_ss_07h_public_github_allowed():
    """SS-07h: legitimate public hosts (allowlist match) pass.

    This is the positive case: a github.com URL must validate.
    """
    req = GenerateRequest(
        source=SourceRef(
            type="git-repository", value="https://github.com/aionrs/api.git"
        )
    )
    req.validate_source()  # no raise
    req2 = GenerateRequest(
        source=SourceRef(
            type="git-repository", value="git@github.com:aionrs/api.git"
        )
    )
    req2.validate_source()


def test_ss_07i_docker_hub_default_allowed():
    """SS-07i: bare image names resolve to docker.io (default registry) and pass."""
    req = GenerateRequest(
        source=SourceRef(type="docker-image", value="nginx:1.25")
    )
    req.validate_source()  # no raise
    req2 = GenerateRequest(
        source=SourceRef(type="oci-image", value="ghcr.io/aionrs/api:v1.0.0")
    )
    req2.validate_source()  # ghcr.io is not private; passes SSRF check


def test_ss_07j_local_paths_unaffected():
    """Local-path sources are never subjected to SSRF checks."""
    for kind, value in (
        ("directory", "/workspace"),
        ("file", "/workspace/Pipfile"),
        ("archive", "/workspace/x.tar.gz"),
    ):
        req = GenerateRequest(source=SourceRef(type=kind, value=value))
        req.validate_source()  # no raise, no SSRF check

