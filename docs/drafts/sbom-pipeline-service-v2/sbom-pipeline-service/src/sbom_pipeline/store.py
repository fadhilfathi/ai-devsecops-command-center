"""Storage layer — SQLite metadata + filesystem object store.

The service persists two kinds of data:

1. **Metadata** (one row per SBOM) in SQLite. The schema is
   intentionally tiny — see ``_INIT_SQL`` below. We use SQLAlchemy
   2.x async + aiosqlite so the same code path works against
   Postgres in production (``SBOM_DB_URL=postgresql+asyncpg://…``).

2. **Raw SBOM blobs** in an object store. In dev that's a local
   directory (``backend/data/sbom-store/``); in prod it's S3.
   The store abstraction in :class:`ObjectStore` is the only thing
   the rest of the code touches.

The store is deliberately split between *metadata* and *payload*:

* Storing the full JSON twice (in SQLite and on disk) is a small
  price for the "give me an SBOM" path being a single SQL
  round-trip and a single FS read.
* Future S2.x work (full-text search, diff between SBOMs) can
  re-derive everything from the payload column.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    func,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sbom_pipeline.errors import SBOMNotFoundError, StorageError
from sbom_pipeline.models import (
    SBOMFormat,
    SBOMRecord,
    parse_source,
)

logger = logging.getLogger("sbom_pipeline.store")


# ---------------------------------------------------------------------------
# Metadata DB
# ---------------------------------------------------------------------------


NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
metadata = MetaData(naming_convention=NAMING_CONVENTION)

sboms = Table(
    "sboms",
    metadata,
    Column("id", String, primary_key=True),
    Column("source", String, nullable=False, index=True),
    Column("format", String, nullable=False),
    Column("data_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, index=True),
    Column("sha256", String(64), nullable=False, index=True),
    Column("size_bytes", BigInteger, nullable=False),
    Column("component_count", Integer, nullable=False, default=0),
    Column("scope", String, nullable=True),
    Column("git_sha", String, nullable=True),
    Column("object_key", String, nullable=True),
)


_INIT_SQL = """
CREATE TABLE IF NOT EXISTS sboms (
    id              TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    format          TEXT NOT NULL,
    data_json       TEXT NOT NULL,
    created_at      DATETIME NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    component_count INTEGER NOT NULL DEFAULT 0,
    scope           TEXT,
    git_sha         TEXT,
    object_key      TEXT
);
CREATE INDEX IF NOT EXISTS ix_sboms_source      ON sboms (source);
CREATE INDEX IF NOT EXISTS ix_sboms_created_at  ON sboms (created_at);
CREATE INDEX IF NOT EXISTS ix_sboms_sha256      ON sboms (sha256);
"""


class SBOMStore:
    """SQLite/Postgres metadata DB for SBOMs."""

    def __init__(self, db_url: str) -> None:
        self._db_url = db_url
        self._engine: Optional[AsyncEngine] = None
        self._session: Optional[async_sessionmaker[AsyncSession]] = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._lock:
            if self._engine is not None:
                return
            self._engine = create_async_engine(
                self._db_url, future=True, pool_pre_ping=True
            )
            self._session = async_sessionmaker(
                self._engine, expire_on_commit=False
            )
            await self._init_schema()

    async def disconnect(self) -> None:
        async with self._lock:
            if self._engine is not None:
                await self._engine.dispose()
            self._engine = None
            self._session = None

    async def _init_schema(self) -> None:
        assert self._engine is not None
        async with self._engine.begin() as conn:
            # We use SQLAlchemy DDL for both backends. The hand-written
            # ``_INIT_SQL`` constant below is kept for devs who want to
            # run ``sqlite3`` by hand, but at runtime we let SQLAlchemy
            # drive — that way aiosqlite's "one statement at a time"
            # limitation can't bite us.
            await conn.run_sync(metadata.create_all)

    async def healthy(self) -> bool:
        if self._engine is None:
            return False
        try:
            async with self._engine.connect() as conn:
                await conn.exec_driver_sql("SELECT 1")
            return True
        except Exception:  # noqa: BLE001
            return False

    # ---- CRUD --------------------------------------------------------------

    async def insert(self, record: SBOMRecord) -> SBOMRecord:
        await self.connect()
        assert self._session is not None
        async with self._session() as session:
            await session.execute(
                sboms.insert().values(
                    id=record.id,
                    source=record.source,
                    format=record.format.value,
                    data_json=record.data_json,
                    created_at=record.created_at,
                    sha256=record.sha256,
                    size_bytes=record.size_bytes,
                    component_count=record.component_count,
                    scope=record.scope,
                    git_sha=record.git_sha,
                    object_key=record.object_key,
                )
            )
            await session.commit()
        return record

    async def get(self, sbom_id: str) -> SBOMRecord:
        await self.connect()
        assert self._session is not None
        async with self._session() as session:
            row = (
                await session.execute(select(sboms).where(sboms.c.id == sbom_id))
            ).first()
            if row is None:
                raise SBOMNotFoundError(
                    f"sbom {sbom_id!r} not found",
                    details={"sbom_id": sbom_id},
                )
            return _row_to_record(row)

    async def find_by_sha(self, sha256: str) -> Optional[SBOMRecord]:
        await self.connect()
        assert self._session is not None
        async with self._session() as session:
            row = (
                await session.execute(
                    select(sboms).where(sboms.c.sha256 == sha256).limit(1)
                )
            ).first()
            if row is None:
                return None
            return _row_to_record(row)

    async def list(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[List[SBOMRecord], int]:
        await self.connect()
        assert self._session is not None
        offset = (page - 1) * page_size
        async with self._session() as session:
            total = (
                await session.execute(select(func.count()).select_from(sboms))
            ).scalar_one()
            rows = (
                await session.execute(
                    select(sboms)
                    .order_by(sboms.c.created_at.desc())
                    .offset(offset)
                    .limit(page_size)
                )
            ).fetchall()
        return [_row_to_record(r) for r in rows], int(total)

    async def delete(self, sbom_id: str) -> bool:
        await self.connect()
        assert self._session is not None
        async with self._session() as session:
            res = await session.execute(
                sboms.delete().where(sboms.c.id == sbom_id)
            )
            await session.commit()
        return res.rowcount > 0


def _row_to_record(row: Any) -> SBOMRecord:
    m = row._mapping
    return SBOMRecord(
        id=m["id"],
        source=m["source"],
        format=SBOMFormat(m["format"]),
        data_json=m["data_json"],
        created_at=m["created_at"],
        sha256=m["sha256"],
        size_bytes=int(m["size_bytes"]),
        component_count=int(m["component_count"] or 0),
        scope=m.get("scope"),
        git_sha=m.get("git_sha"),
        object_key=m.get("object_key"),
    )


# ---------------------------------------------------------------------------
# Object store
# ---------------------------------------------------------------------------


class ObjectStore:
    """Filesystem- or S3-backed blob store for raw SBOM payloads.

    The default is the local filesystem. Production deployments
    override via ``SBOM_OBJECT_STORE=s3://bucket/prefix``.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._root: Optional[Path] = None
        self._s3: Any = None
        self._s3_bucket: Optional[str] = None
        self._s3_prefix: Optional[str] = None
        self._parse(url)

    def _parse(self, url: str) -> None:
        if url.startswith("s3://"):
            # Lazy import — boto3 is heavy and not needed in dev.
            import boto3  # type: ignore[import-not-found]

            bucket, _, prefix = url[len("s3://"):].partition("/")
            self._s3 = boto3.client("s3")
            self._s3_bucket = bucket
            self._s3_prefix = prefix
        else:
            self._root = Path(url)
            self._root.mkdir(parents=True, exist_ok=True)

    @property
    def backend(self) -> str:
        return "s3" if self._s3 is not None else "fs"

    async def put(self, key: str, data: bytes) -> str:
        if self._s3 is not None:
            assert self._s3_bucket is not None
            full_key = f"{self._s3_prefix or ''}{key}"
            await asyncio.to_thread(
                self._s3.put_object,
                Bucket=self._s3_bucket,
                Key=full_key,
                Body=data,
            )
            return f"s3://{self._s3_bucket}/{full_key}"
        assert self._root is not None
        path = self._root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(path.write_bytes, data)
        return str(path)

    async def get(self, key: str) -> bytes:
        if self._s3 is not None:
            assert self._s3_bucket is not None
            full_key = f"{self._s3_prefix or ''}{key}"
            resp = await asyncio.to_thread(
                self._s3.get_object,
                Bucket=self._s3_bucket,
                Key=full_key,
            )
            return resp["Body"].read()
        assert self._root is not None
        return await asyncio.to_thread((self._root / key).read_bytes)

    async def delete(self, key: str) -> None:
        if self._s3 is not None:
            assert self._s3_bucket is not None
            full_key = f"{self._s3_prefix or ''}{key}"
            await asyncio.to_thread(
                self._s3.delete_object,
                Bucket=self._s3_bucket,
                Key=full_key,
            )
            return
        assert self._root is not None
        path = self._root / key
        if path.exists():
            await asyncio.to_thread(path.unlink)

    async def healthy(self) -> bool:
        if self._s3 is not None:
            try:
                await asyncio.to_thread(
                    self._s3.head_bucket, Bucket=self._s3_bucket
                )
                return True
            except Exception:  # noqa: BLE001
                return False
        assert self._root is not None
        return self._root.exists() and os.access(self._root, os.W_OK)


# ---------------------------------------------------------------------------
# Combined façade
# ---------------------------------------------------------------------------


class SBOMRepository:
    """The two stores used together — metadata + payload."""

    def __init__(self, db: SBOMStore, objects: ObjectStore) -> None:
        self._db = db
        self._objects = objects

    @property
    def db(self) -> SBOMStore:
        return self._db

    @property
    def objects(self) -> ObjectStore:
        return self._objects

    async def healthy(self) -> Dict[str, bool]:
        return {
            "db": await self._db.healthy(),
            "objects": await self._objects.healthy(),
        }
