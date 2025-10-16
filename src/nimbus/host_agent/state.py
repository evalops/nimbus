"""Persistent state tracking for the Nimbus host agent."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog
from sqlalchemy import BigInteger, Column, DateTime, Integer, MetaData, String, Table, delete, insert, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

LOGGER = structlog.get_logger("nimbus.host_agent.state")


metadata = MetaData()


agent_jobs_table = Table(
    "agent_jobs",
    metadata,
    Column("job_id", BigInteger, primary_key=True),
    Column("tap_name", String(length=64), nullable=False),
    Column("bridge", String(length=64), nullable=False),
    Column("host_ip", String(length=64), nullable=False),
    Column("guest_ip", String(length=64), nullable=False),
    Column("cidr", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


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
    """SQL-backed persistence for active job state."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker[AsyncSession]] = None
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        async with self._lock:
            if self._engine is not None:
                return

            url = make_url(self._database_url)
            if url.drivername.startswith("sqlite") and url.database:
                sqlite_path = Path(url.database).expanduser()
                sqlite_path.parent.mkdir(parents=True, exist_ok=True)

            self._engine = create_async_engine(self._database_url, future=True, echo=False)
            self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
            async with self._engine.begin() as conn:
                await conn.run_sync(metadata.create_all)
            LOGGER.debug("Agent state store initialised", url=self._database_url)

    async def close(self) -> None:
        async with self._lock:
            if self._engine is None:
                return
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    async def record_job(self, job: StoredJobNetwork) -> None:
        session_factory = self._session_factory
        if session_factory is None:
            raise RuntimeError("AgentStateStore not opened")

        now = datetime.now(timezone.utc)
        async with session_factory() as session:
            await session.execute(
                delete(agent_jobs_table).where(agent_jobs_table.c.job_id == job.job_id)
            )
            await session.execute(
                insert(agent_jobs_table).values(
                    job_id=job.job_id,
                    tap_name=job.tap_name,
                    bridge=job.bridge,
                    host_ip=job.host_ip,
                    guest_ip=job.guest_ip,
                    cidr=job.cidr,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()
        LOGGER.debug("Recorded job state", job_id=job.job_id, tap=job.tap_name)

    async def remove_job(self, job_id: int) -> None:
        session_factory = self._session_factory
        if session_factory is None:
            raise RuntimeError("AgentStateStore not opened")

        async with session_factory() as session:
            await session.execute(delete(agent_jobs_table).where(agent_jobs_table.c.job_id == job_id))
            await session.commit()
        LOGGER.debug("Removed job state", job_id=job_id)

    async def list_jobs(self) -> list[StoredJobNetwork]:
        session_factory = self._session_factory
        if session_factory is None:
            raise RuntimeError("AgentStateStore not opened")

        async with session_factory() as session:
            result = await session.execute(
                select(
                    agent_jobs_table.c.job_id,
                    agent_jobs_table.c.tap_name,
                    agent_jobs_table.c.bridge,
                    agent_jobs_table.c.host_ip,
                    agent_jobs_table.c.guest_ip,
                    agent_jobs_table.c.cidr,
                )
            )
            rows = list(result)

        return [
            StoredJobNetwork(
                job_id=row.job_id,
                tap_name=row.tap_name,
                bridge=row.bridge,
                host_ip=row.host_ip,
                guest_ip=row.guest_ip,
                cidr=row.cidr,
            )
            for row in rows
        ]
