"""Utilities for temporary database sessions in tests."""

from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from src.nimbus.control_plane.db import create_engine, session_factory


@asynccontextmanager
async def temp_session(*metadatas) -> AsyncSession:
    """
    Yield an async SQLAlchemy session backed by an ephemeral SQLite database.

    Args:
        *metadatas: SQLAlchemy MetaData objects to create before yielding.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "nimbus-test.db"
        engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            for meta in metadatas:
                await conn.run_sync(meta.create_all)
        Session = session_factory(engine)
        try:
            async with Session() as session:
                yield session
        finally:
            await engine.dispose()
