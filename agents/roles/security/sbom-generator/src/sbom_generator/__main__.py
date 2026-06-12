"""Allow ``python -m sbom_generator`` to launch the service."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from sbom_generator.service import create_app
from sbom_generator.config import Settings

logger = logging.getLogger("sbom_generator")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sbom_generator",
        description="Syft-wrapped SBOM generation service.",
    )
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "4007")),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("WORKERS", "1")),
    )
    parser.add_argument(
        "--syft-binary",
        default=os.environ.get("SYFT_BINARY", "syft"),
        help="Path to the Syft binary (default: lookup on $PATH).",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable hot reload (development only).",
    )
    parser.add_argument(
        "--bus-url",
        default=os.environ.get("BUS_URL", "nats://localhost:4222"),
        help="URL of the event bus (NATS or Redis).",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
    # Import uvicorn lazily so that library users don't need it installed.
    try:
        import uvicorn
    except ImportError:  # pragma: no cover
        logger.error(
            "uvicorn is required to run the HTTP service. "
            "Install it with `pip install uvicorn[standard]`."
        )
        return 2

    settings = Settings(
        syft_binary=args.syft_binary,
        bus_url=args.bus_url,
        host=args.host,
        port=args.port,
    )
    app = create_app(settings=settings)

    logger.info(
        "Starting SBOM generator on %s:%d (syft=%s, bus=%s)",
        args.host,
        args.port,
        args.syft_binary,
        args.bus_url,
    )
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=args.workers,
        reload=args.reload,
        log_level=args.log_level.lower(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
