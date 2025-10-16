"""Persistent state tracking for the Nimbus host agent."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aiosqlite
import structlog

LOGGER = structlog.get_logger("nimbus.host_agent.state")


@dataclass(slots=True)
class StoredJobNetwork:
    """Network resources associated with an in-flight job."""

    job_id: int
    tap_name: str
    bridge: str
    host_ip: str
    guest_ip: str
    cidr: int


class AgentStateStore:
    """Lightweight SQLite-backed persistence for active job state."""

    def __init__(self, path: Path) -> None:
        self._path = path.expanduser()
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        if self._db is not None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._path)
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id INTEGER PRIMARY KEY,
                tap_name TEXT NOT NULL,
                bridge TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                guest_ip TEXT NOT NULL,
                cidr INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await self._db.commit()
        LOGGER.debug("Agent state store initialised", path=str(self._path))

    async def close(self) -> None:
        if self._db is None:
            return
        await self._db.close()
        self._db = None

    async def record_job(self, job: StoredJobNetwork) -> None:
        if self._db is None:
            raise RuntimeError("AgentStateStore not opened")
        async with self._lock:
            await self._db.execute(
                """
                INSERT OR REPLACE INTO jobs (job_id, tap_name, bridge, host_ip, guest_ip, cidr)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job.job_id, job.tap_name, job.bridge, job.host_ip, job.guest_ip, job.cidr),
            )
            await self._db.commit()
            LOGGER.debug("Recorded job state", job_id=job.job_id, tap=job.tap_name)

    async def remove_job(self, job_id: int) -> None:
        if self._db is None:
            raise RuntimeError("AgentStateStore not opened")
        async with self._lock:
            await self._db.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
            await self._db.commit()
            LOGGER.debug("Removed job state", job_id=job_id)

    async def list_jobs(self) -> list[StoredJobNetwork]:
        if self._db is None:
            raise RuntimeError("AgentStateStore not opened")
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT job_id, tap_name, bridge, host_ip, guest_ip, cidr FROM jobs"
            )
            rows = await cursor.fetchall()
            await cursor.close()
        return [
            StoredJobNetwork(
                job_id=row[0],
                tap_name=row[1],
                bridge=row[2],
                host_ip=row[3],
                guest_ip=row[4],
                cidr=row[5],
            )
            for row in rows
        ]
