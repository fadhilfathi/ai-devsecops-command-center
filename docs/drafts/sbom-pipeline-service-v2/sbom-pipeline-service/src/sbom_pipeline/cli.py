"""Click CLI — ``python -m sbom_pipeline ...``.

Commands mirror the HTTP API for parity:

* ``generate`` — call ``POST /sbom/generate`` against a running service
* ``analyze``  — call ``POST /sbom/analyze``
* ``list``     — call ``GET /sbom``
* ``get``      — call ``GET /sbom/{id}``
* ``delete``   — call ``DELETE /sbom/{id}``
* ``serve``    — run the FastAPI service locally

The HTTP mode assumes ``SBOM_ENDPOINT`` is set (default
``http://127.0.0.1:4007``). For offline use, ``--offline`` runs the
same logic in-process via the service factory.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import click
import httpx

from sbom_pipeline.__init__ import __version__
from sbom_pipeline.config import Settings
from sbom_pipeline.models import (
    AnalyzeRequest,
    GenerateRequest,
    parse_source,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _http() -> httpx.Client:
    endpoint = os.environ.get("SBOM_ENDPOINT", "http://127.0.0.1:4007")
    return httpx.Client(base_url=endpoint, timeout=httpx.Timeout(700.0))


def _print_json(payload: Any) -> None:
    click.echo(json.dumps(payload, indent=2, default=str, sort_keys=True))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group(help="AionRs SBOM pipeline CLI.", context_settings={"max_content_width": 120})
@click.version_option(__version__, prog_name="sbom-pipeline")
def main() -> None:
    pass


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


@main.command(help="Generate an SBOM for a docker/git/fs/lockfile source.")
@click.option(
    "--source",
    required=True,
    help="Source string with prefix: docker:… | git:… | fs:… | lockfile:…",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(
        ["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value", "syft-json"]
    ),
    default="cyclonedx-json",
)
@click.option("--scope", default="monorepo", help="sbom_id scope component.")
@click.option("--git-sha", default=None, help="Short git SHA for the sbom_id.")
@click.option("--offline", is_flag=True, help="Run the service in-process.")
@click.option("--save", type=click.Path(), default=None, help="Save the SBOM body to a file.")
def generate_cmd(
    source: str,
    fmt: str,
    scope: str,
    git_sha: Optional[str],
    offline: bool,
    save: Optional[str],
) -> None:
    body = {
        "source": source,
        "format": fmt,
        "scope": scope,
        "git_sha": git_sha,
    }
    if offline:
        result = asyncio.run(_generate_offline(body))
    else:
        with _http() as client:
            r = client.post("/sbom/generate", json=body)
            r.raise_for_status()
            result = r.json()
    click.echo(f"✅ {result['sbom_id']}  components={result['component_count']}  size={result['size_bytes']}B")
    if save:
        Path(save).write_text(
            json.dumps(result["data"], indent=2) if isinstance(result["data"], (dict, list))
            else str(result["data"]),
            encoding="utf-8",
        )
        click.echo(f"   saved to {save}")


async def _generate_offline(body: Dict[str, Any]) -> Dict[str, Any]:
    from fastapi.testclient import TestClient

    from sbom_pipeline.main import create_app
    from sbom_pipeline.config import Settings

    # Force an in-memory bus for the offline run.
    settings = Settings(
        bus_url="memory://",
        db_url="sqlite+aiosqlite:///:memory:",
        object_store_url="fs:///tmp/sbom-cli-store",
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        r = client.post("/sbom/generate", json=body)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@main.command(help="Analyze a stored SBOM (component count, depth, licenses, …).")
@click.option("--sbom-id", required=True)
@click.option("--offline", is_flag=True)
def analyze(sbom_id: str, offline: bool) -> None:
    body = {"sbom_id": sbom_id}
    if offline:
        result = asyncio.run(_analyze_offline(body))
    else:
        with _http() as client:
            r = client.post("/sbom/analyze", json=body)
            r.raise_for_status()
            result = r.json()
    _print_json(result)


async def _analyze_offline(body: Dict[str, Any]) -> Dict[str, Any]:
    from fastapi.testclient import TestClient

    from sbom_pipeline.main import create_app
    from sbom_pipeline.config import Settings

    settings = Settings(bus_url="memory://", db_url="sqlite+aiosqlite:///:memory:")
    app = create_app(settings=settings)
    with TestClient(app) as client:
        r = client.post("/sbom/analyze", json=body)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@main.command("list", help="List stored SBOMs.")
@click.option("--page", default=1, type=int)
@click.option("--page-size", default=20, type=int)
def list_cmd(page: int, page_size: int) -> None:
    with _http() as client:
        r = client.get("/sbom", params={"page": page, "page_size": page_size})
        r.raise_for_status()
        data = r.json()
    click.echo(
        f"{'SBOM ID':<60}  {'SOURCE':<40}  {'FORMAT':<18}  {'COMP':>5}  CREATED"
    )
    click.echo("-" * 140)
    for item in data["items"]:
        click.echo(
            f"{item['id']:<60}  {item['source']:<40}  {item['format']:<18}  "
            f"{item.get('component_count', 0):>5}  {item['created_at']}"
        )
    click.echo(f"\npage {data['page']}/{data['total'] // data['page_size'] + 1}  "
               f"(total={data['total']})")


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


@main.command(help="Retrieve a stored SBOM.")
@click.option("--sbom-id", required=True)
@click.option("--format", "fmt", default="cyclonedx-json")
@click.option("--output", type=click.Path(), default=None)
def get(sbom_id: str, fmt: str, output: Optional[str]) -> None:
    with _http() as client:
        r = client.get(f"/sbom/{sbom_id}", params={"format": fmt})
        r.raise_for_status()
        text = r.text
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(f"saved to {output}")
    else:
        click.echo(text)


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


@main.command(help="Delete a stored SBOM.")
@click.option("--sbom-id", required=True)
@click.confirmation_option(prompt="Are you sure?")
def delete(sbom_id: str) -> None:
    with _http() as client:
        r = client.delete(f"/sbom/{sbom_id}")
        r.raise_for_status()
        click.echo(f"deleted {sbom_id}")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@main.command(help="Run the FastAPI service.")
@click.option("--host", default=None)
@click.option("--port", default=None, type=int)
@click.option("--reload", is_flag=True)
def serve(host: Optional[str], port: Optional[int], reload: bool) -> None:
    import uvicorn

    settings = Settings()
    uvicorn.run(
        "sbom_pipeline.main:create_app",
        factory=True,
        host=host or settings.host,
        port=port or settings.port,
        reload=reload,
    )


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    main()
