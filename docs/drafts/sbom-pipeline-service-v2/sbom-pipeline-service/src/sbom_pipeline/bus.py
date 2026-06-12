"""Event bus publisher — wraps the Sprint 1 EventBus contract.

The service emits on these subjects (Lead-locked + GitOpsManager
contract):

* ``security.sbom.requested.v1`` — inbound, from the platform
* ``security.sbom.generated.v1`` — outbound, after a successful scan
* ``security.sbom.failed.v1``    — outbound, on scan error
* ``security.sbom.analyzed.v1``   — outbound, after the analyzer runs
* ``security.sbom.stored.v1``    — outbound, after persisting a new SBOM

The bus client implements a minimal interface so we can swap NATS
for Redis Streams, in-memory, or the Sprint 1 EventBus without
touching the rest of the code.

A best-effort publisher is used by default — a failed publish never
breaks a successful scan, only logs a warning.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("sbom_pipeline.bus")


# ---------------------------------------------------------------------------
# Bus client interface
# ---------------------------------------------------------------------------


class BusClient:
    """Minimal interface every bus implementation must satisfy."""

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def publish(self, subject: str, payload: Dict[str, Any]) -> str: ...
    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
        queue: Optional[str] = None,
    ) -> None: ...
    async def healthy(self) -> bool: ...


class InMemoryBus(BusClient):
    """In-process bus for development and tests.

    Uses :class:`asyncio.Queue` semantics — every subscriber
    receives a copy. In a real broker the queue-group would
    load-balance.
    """

    def __init__(self) -> None:
        self._subs: Dict[str, List[Callable[[Dict[str, Any]], Awaitable[None]]]] = {}
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def close(self) -> None:
        self._connected = False
        self._subs.clear()

    async def publish(self, subject: str, payload: Dict[str, Any]) -> str:
        if not self._connected:
            raise RuntimeError("bus not connected")
        import uuid

        msg_id = str(uuid.uuid4())
        await asyncio.sleep(0)
        for handler in list(self._subs.get(subject, [])):
            asyncio.create_task(handler({**payload, "_id": msg_id, "_subject": subject}))
        return msg_id

    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
        queue: Optional[str] = None,
    ) -> None:
        self._subs.setdefault(subject, []).append(handler)

    async def healthy(self) -> bool:
        return self._connected


class NATSClient(BusClient):
    """Thin NATS client wrapper.

    The real Sprint 1 EventBus lives in the shared bus package; this
    is the contract the S2.1 service uses when run standalone.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._nc: Any = None
        self._js: Any = None

    async def connect(self) -> None:
        try:
            import nats  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "nats-py is not installed; install with `pip install nats-py`"
            ) from exc
        self._nc = await nats.connect(self._url)
        try:
            self._js = self._nc.jetstream()
        except Exception:  # noqa: BLE001
            self._js = None

    async def close(self) -> None:
        if self._nc is not None:
            await self._nc.close()
            self._nc = None
            self._js = None

    async def publish(self, subject: str, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, default=str).encode("utf-8")
        if self._js is not None:
            ack = await self._js.publish(subject, body)
            return str(ack.seq)
        if self._nc is not None:
            await self._nc.publish(subject, body)
            return f"nats:{int(time.time() * 1e6)}"
        raise RuntimeError("bus not connected")

    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
        queue: Optional[str] = None,
    ) -> None:
        async def _wrapped(msg: Any) -> None:
            try:
                payload = json.loads(msg.data.decode("utf-8"))
            except Exception:  # noqa: BLE001
                payload = {"_raw": msg.data.decode("utf-8", errors="replace")}
            await handler(payload)

        if self._js is not None:
            await self._js.subscribe(subject, cb=_wrapped, queue=queue)
        elif self._nc is not None:
            await self._nc.subscribe(subject, cb=_wrapped, queue=queue)
        else:
            raise RuntimeError("bus not connected")

    async def healthy(self) -> bool:
        return self._nc is not None and not self._nc.is_closed


def build_bus(url: str) -> BusClient:
    """Factory: pick the right bus implementation from a URL string."""
    if not url or url.startswith("memory://"):
        return InMemoryBus()
    return NATSClient(url)


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------


@dataclass
class BusPublisher:
    """Thin façade over a :class:`BusClient` that adds schema tags."""

    bus: BusClient
    service: str = "sbom-pipeline"
    failed: List[Dict[str, Any]] = field(default_factory=list)

    async def connect(self) -> None:
        await self.bus.connect()

    async def close(self) -> None:
        await self.bus.close()

    async def healthy(self) -> bool:
        try:
            return await self.bus.healthy()
        except Exception:  # noqa: BLE001
            return False

    async def publish_event(
        self, subject: str, payload: Dict[str, Any]
    ) -> Optional[str]:
        """Publish a v1 event with the schema tag baked in.

        Returns the message id on success, or ``None`` on failure.
        """
        # The "schema" field is the versioned schema tag, matching
        # the contract the GitOpsManager auto-committer reads.
        if not subject.endswith(".v1"):
            logger.warning(
                "publishing to non-v1 subject %s — consider renaming", subject
            )
        try:
            return await self.bus.publish(
                subject,
                {
                    "schema": subject,
                    "service": self.service,
                    "ts": time.time(),
                    **payload,
                },
            )
        except Exception as exc:  # noqa: BLE001
            self.failed.append({"subject": subject, "error": str(exc)})
            logger.warning("bus publish failed for %s: %s", subject, exc)
            return None
