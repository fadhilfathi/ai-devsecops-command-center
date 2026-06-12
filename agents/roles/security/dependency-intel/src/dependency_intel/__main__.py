"""Service entrypoint — ``python -m dependency_intel``."""
from __future__ import annotations

import signal
import sys
from typing import Any

import uvicorn

from .api.app import create_app
from .config import get_settings
from .telemetry import configure_logging, get_logger


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger("dependency_intel")
    logger.info(
        "service_starting host=%s port=%s tenant=%s data_dir=%s vuln_intel_url=%s",
        settings.host, settings.port, settings.tenant_id, str(settings.data_dir), settings.vuln_intel_url,
    )

    config = uvicorn.Config(
        app=create_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
        timeout_graceful_shutdown=10,
    )
    server = uvicorn.Server(config)

    def _shutdown(signum: int, _frame: Any) -> None:
        logger.info("shutdown_signal_received signum=%s", signum)
        server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass

    server.run()
    logger.info("service_stopped")
    sys.exit(0)


if __name__ == "__main__":
    main()
