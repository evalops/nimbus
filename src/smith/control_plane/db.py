"""Async database helpers for the Smith control plane."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    DateTime,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..common.schemas import JobAssignment, JobStatusUpdate


metadata = MetaData()


jobs_table = Table(
    "jobs",
    metadata,
    Column("job_id", BigInteger, primary_key=True),
    Column("run_id", BigInteger, nullable=False),
    Column("run_attempt", BigInteger, nullable=False, default=1),
    Column("repo_id", BigInteger, nullable=False),
    Column("repo_full_name", String(length=512), nullable=False),
    Column("repo_private", String(length=5), nullable=False),
    Column("labels", JSON(none_as_null=True)),
    Column("status", String(length=32), nullable=False),
    Column("agent_id", String(length=128), nullable=True),
    Column("queued_at", DateTime(timezone=True), nullable=False),
    Column("leased_at", DateTime(timezone=True), nullable=True),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    Column("last_message", Text, nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


def create_engine(database_url: str) -> AsyncEngine:
    return create_async_engine(database_url, future=True, echo=False)


async def ensure_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def record_job_queued(session: AsyncSession, assignment: JobAssignment) -> None:
    now = datetime.now(timezone.utc)
    repo = assignment.repository
    stmt = insert(jobs_table).values(
        job_id=assignment.job_id,
        run_id=assignment.run_id,
        run_attempt=assignment.run_attempt,
        repo_id=repo.id,
        repo_full_name=repo.full_name,
        repo_private="true" if repo.private else "false",
        labels=assignment.labels,
        status="queued",
        agent_id=None,
        queued_at=now,
        leased_at=None,
        completed_at=None,
        last_message=None,
        updated_at=now,
    )
    await session.execute(stmt)


async def mark_job_leased(
    session: AsyncSession, job_id: int, agent_id: str, *, backfill_status: Optional[str] = None
) -> None:
    now = datetime.now(timezone.utc)
    stmt = (
        update(jobs_table)
        .where(jobs_table.c.job_id == job_id)
        .values(
            agent_id=agent_id,
            status=backfill_status or "leased",
            leased_at=now,
            updated_at=now,
        )
    )
    await session.execute(stmt)


async def record_status_update(session: AsyncSession, update_payload: JobStatusUpdate) -> None:
    now = datetime.now(timezone.utc)
    values = {
        "status": update_payload.status,
        "agent_id": update_payload.agent_id,
        "updated_at": now,
        "last_message": update_payload.message,
    }
    if update_payload.status in {"succeeded", "failed", "cancelled"}:
        values["completed_at"] = now
    stmt = update(jobs_table).where(jobs_table.c.job_id == update_payload.job_id).values(**values)
    await session.execute(stmt)


async def list_recent_jobs(
    session: AsyncSession, limit: int = 50
) -> Iterable[dict]:
    stmt = (
        select(jobs_table)
        .order_by(jobs_table.c.updated_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    rows = [dict(row) for row in result.mappings()]
    for row in rows:
        row["repo_private"] = True if row.get("repo_private") == "true" else False
        for key in ("queued_at", "leased_at", "completed_at", "updated_at"):
            value = row.get(key)
            if isinstance(value, datetime):
                row[key] = value.isoformat()
    return rows
