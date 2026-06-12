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
