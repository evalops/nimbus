"""Async database helpers for the Nimbus control plane."""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timezone, timedelta
from typing import Iterable, Optional

import structlog
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Integer,
    DateTime,
    Index,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    Float,
    func,
    insert,
    select,
    update,
    and_,
    case,
    cast,
)
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.engine.url import make_url

from ..common.schemas import JobAssignment, JobStatusUpdate


metadata = MetaData()


def _json_path_for_metadata(key: str) -> str:
    escaped = key.replace('"', '\\"')
    return f'$."{escaped}"'


jobs_table = Table(
    "jobs",
    metadata,
    Column("job_id", BigInteger, primary_key=True),
    Column("run_id", BigInteger, nullable=False),
    Column("run_attempt", BigInteger, nullable=False, default=1),
    Column("repo_id", BigInteger, nullable=False),
    Column("org_id", BigInteger, nullable=True),
    Column("repo_full_name", String(length=512), nullable=False),
    Column("repo_private", String(length=5), nullable=False),
    Column("labels", JSON(none_as_null=True)),
    Column("metadata", JSON(none_as_null=True)),
    Column("executor", String(length=32), nullable=False, default="firecracker"),
    Column("status", String(length=32), nullable=False),
    Column("agent_id", String(length=128), nullable=True),
    Column("queued_at", DateTime(timezone=True), nullable=False),
    Column("leased_at", DateTime(timezone=True), nullable=True),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    Column("last_message", Text, nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


agent_credentials_table = Table(
    "agent_credentials",
    metadata,
    Column("agent_id", String(length=128), primary_key=True),
    Column("token_version", Integer, nullable=False, default=1),
    Column("rotated_at", DateTime(timezone=True), nullable=False),
    Column("ttl_seconds", Integer, nullable=False),
)


agent_token_audit_table = Table(
    "agent_token_audit",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("agent_id", String(length=128), nullable=False),
    Column("rotated_by", String(length=128), nullable=False),
    Column("token_version", Integer, nullable=False),
    Column("rotated_at", DateTime(timezone=True), nullable=False),
    Column("ttl_seconds", Integer, nullable=False),
)


ssh_sessions_table = Table(
    "ssh_sessions",
    metadata,
    Column("session_id", String(length=64), primary_key=True),
    Column("job_id", BigInteger, nullable=False),
    Column("agent_id", String(length=128), nullable=False),
    Column("host_port", Integer, nullable=False),
    Column("token", String(length=128), nullable=False),
    Column("authorized_user", String(length=128), nullable=False),
    Column("status", String(length=32), nullable=False),
    Column("vm_ip", String(length=64), nullable=True),
    Column("reason", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("agent_id", "host_port", name="uq_ssh_agent_port"),
    Index("ix_ssh_agent_status_expires", "agent_id", "status", "expires_at"),
)


job_leases_table = Table(
    "job_leases",
    metadata,
    Column("job_id", BigInteger, primary_key=True),
    Column("agent_id", String(length=128), nullable=False),
    Column("version", Integer, nullable=False),
    Column("lease_expires_at", DateTime(timezone=True), nullable=False),
    Column("heartbeat_at", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_job_leases_expires", "lease_expires_at"),
)


def create_engine(database_url: str) -> AsyncEngine:
    url = make_url(database_url)
    engine_kwargs: dict[str, object] = {
        "future": True,
        "echo": False,
        "pool_pre_ping": True,
    }
    if url.get_backend_name() not in {"sqlite", "sqlite+aiosqlite"}:
        engine_kwargs.update(
            {
                "pool_size": 20,
                "max_overflow": 40,
                "pool_timeout": 30,
                "pool_recycle": 1800,
            }
        )
    return create_async_engine(database_url, **engine_kwargs)


async def ensure_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def _normalise_job_rows(rows: Iterable[dict]) -> list[dict]:
    normalised: list[dict] = []
    for row in rows:
        payload = dict(row)
        payload["repo_private"] = True if payload.get("repo_private") == "true" else False
        metadata = payload.get("metadata")
        payload["metadata"] = metadata if isinstance(metadata, dict) else {}
        for key in ("queued_at", "leased_at", "completed_at", "updated_at"):
            value = payload.get(key)
            if isinstance(value, datetime):
                payload[key] = value.isoformat()
        normalised.append(payload)
    return normalised


async def record_job_queued(session: AsyncSession, assignment: JobAssignment) -> None:
    now = datetime.now(timezone.utc)
    repo = assignment.repository
    stmt = insert(jobs_table).values(
        job_id=assignment.job_id,
        run_id=assignment.run_id,
        run_attempt=assignment.run_attempt,
        repo_id=repo.id,
        org_id=repo.owner_id or repo.id,
        repo_full_name=repo.full_name,
        repo_private="true" if repo.private else "false",
        labels=assignment.labels,
        executor=assignment.executor,
        status="queued",
        agent_id=None,
        queued_at=now,
        leased_at=None,
        completed_at=None,
        last_message=None,
        updated_at=now,
        metadata=assignment.metadata,
    )
    await session.execute(stmt)


async def mark_job_leased(
    session: AsyncSession, job_id: int, agent_id: str, *, backfill_status: Optional[str] = None
) -> bool:
    """
    Mark a job as leased. Only succeeds if job is currently in queued status.
    Returns True if the job was marked as leased, False if it was already leased or in another state.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        update(jobs_table)
        .where(
            and_(
                jobs_table.c.job_id == job_id,
                jobs_table.c.status == "queued",
            )
        )
        .values(
            agent_id=agent_id,
            status=backfill_status or "leased",
            leased_at=now,
            updated_at=now,
        )
    )
    result = await session.execute(stmt)
    return result.rowcount > 0


async def record_status_update(session: AsyncSession, update_payload: JobStatusUpdate) -> None:
    now = datetime.now(timezone.utc)
    values = {
        "status": update_payload.status,
        "agent_id": update_payload.agent_id,
        "updated_at": now,
        "last_message": update_payload.message,
    }
    is_terminal = update_payload.status in {"succeeded", "failed", "cancelled"}
    if is_terminal:
        values["completed_at"] = now

    if update_payload.metadata:
        result = await session.execute(
            select(jobs_table.c.metadata).where(jobs_table.c.job_id == update_payload.job_id)
        )
        current_metadata = result.scalar_one_or_none() or {}
        merged_metadata: dict[str, str] = {}
        if isinstance(current_metadata, dict):
            merged_metadata.update({str(key): str(value) for key, value in current_metadata.items() if value is not None})
        for key, value in update_payload.metadata.items():
            if value is None:
                continue
            merged_metadata[str(key)] = str(value)
        values["metadata"] = merged_metadata

    stmt = update(jobs_table).where(jobs_table.c.job_id == update_payload.job_id).values(**values)
    await session.execute(stmt)

    # Release lease on terminal states to prevent leak
    if is_terminal and update_payload.fence_token is not None:
        await release_job_lease(session, update_payload.job_id, update_payload.agent_id, update_payload.fence_token)


async def list_recent_jobs(
    session: AsyncSession,
    limit: int = 50,
    org_id: Optional[int] = None,
    *,
    status: Optional[str] = None,
    label: Optional[str] = None,
    metadata_key: Optional[str] = None,
    metadata_value: Optional[str] = None,
) -> Iterable[dict]:
    stmt = (
        select(jobs_table)
        .order_by(jobs_table.c.updated_at.desc())
        .limit(limit)
    )
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    result = await session.execute(stmt)
    rows = [dict(row) for row in result.mappings()]
    normalised = _normalise_job_rows(rows)
    if status:
        normalised = [row for row in normalised if row.get("status") == status]
    if label:
        normalised = [
            row
            for row in normalised
            if label in (row.get("labels") or [])
        ]
    if metadata_key:
        key = metadata_key
        normalised = [
            row
            for row in normalised
            if key in (row.get("metadata") or {})
            and (
                metadata_value is None
                or str((row.get("metadata") or {}).get(key)) == metadata_value
            )
        ]
    elif metadata_value is not None:
        normalised = [
            row
            for row in normalised
            if metadata_value in {str(value) for value in (row.get("metadata") or {}).values()}
        ]
    return normalised


async def top_jobs_by_numeric_metadata(
    session: AsyncSession,
    key: str,
    limit: int = 5,
    org_id: Optional[int] = None,
) -> list[dict]:
    limit = max(1, min(limit, 50))
    path = _json_path_for_metadata(key)
    json_value = func.json_extract(jobs_table.c.metadata, path)
    value_expr = cast(json_value, Float)
    stmt = (
        select(
            jobs_table.c.job_id,
            jobs_table.c.repo_full_name,
            jobs_table.c.status,
            jobs_table.c.completed_at,
            value_expr.label("metric_value"),
        )
        .where(json_value.isnot(None))
    )
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    stmt = stmt.order_by(value_expr.desc()).limit(limit)
    result = await session.execute(stmt)
    rows = []
    for row in result.mappings():
        metric_value = row["metric_value"]
        completed_at = row["completed_at"]
        if isinstance(completed_at, datetime):
            completed_str = completed_at.isoformat()
        else:
            completed_str = completed_at
        rows.append(
            {
                "job_id": row["job_id"],
                "repo_full_name": row["repo_full_name"],
                "status": row["status"],
                "completed_at": completed_str,
                "value": float(metric_value) if metric_value is not None else None,
            }
        )
    return rows


async def average_numeric_metadata(
    session: AsyncSession,
    key: str,
    limit: int = 200,
    org_id: Optional[int] = None,
) -> Optional[float]:
    limit = max(1, min(limit, 1000))
    path = _json_path_for_metadata(key)
    json_value = func.json_extract(jobs_table.c.metadata, path)
    value_expr = cast(json_value, Float)
    stmt = select(value_expr.label("value")).where(json_value.isnot(None))
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    stmt = stmt.order_by(jobs_table.c.updated_at.desc()).limit(limit)
    subquery = stmt.subquery()
    result = await session.execute(select(func.avg(subquery.c.value)))
    avg_value = result.scalar_one_or_none()
    return float(avg_value) if avg_value is not None else None


async def job_metadata_since(session: AsyncSession, since: datetime) -> list[dict]:
    stmt = (
        select(jobs_table.c.job_id, jobs_table.c.metadata, jobs_table.c.completed_at)
        .where(jobs_table.c.completed_at.isnot(None))
        .where(jobs_table.c.completed_at >= since)
    )
    result = await session.execute(stmt)
    rows = [dict(row) for row in result.mappings()]
    return _normalise_job_rows(rows)


async def metadata_outcomes(
    session: AsyncSession,
    key: str,
    *,
    org_id: Optional[int] = None,
    hours_back: Optional[int] = None,
    limit: int = 20,
) -> list[dict]:
    value_expr = cast(jobs_table.c.metadata[key], String)
    if value_expr is None:
        return []

    total_case = func.count().label("total")
    succeeded_case = func.sum(
        case((jobs_table.c.status == "succeeded", 1), else_=0)
    ).label("succeeded")
    failed_case = func.sum(
        case((jobs_table.c.status == "failed", 1), else_=0)
    ).label("failed")

    stmt = (
        select(
            value_expr.label("value"),
            total_case,
            succeeded_case,
            failed_case,
        )
        .where(value_expr.isnot(None))
    )
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    if hours_back is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        stmt = stmt.where(jobs_table.c.updated_at >= cutoff)
    stmt = (
        stmt.group_by(value_expr)
        .order_by(total_case.desc())
        .limit(max(1, limit))
    )
    result = await session.execute(stmt)
    buckets: list[dict] = []
    for row in result.mappings():
        value = row.get("value")
        if isinstance(value, str) and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        buckets.append(
            {
                "value": value,
                "total": int(row.get("total") or 0),
                "succeeded": int(row.get("succeeded") or 0),
                "failed": int(row.get("failed") or 0),
            }
        )
    return buckets


async def job_status_counts(
    session: AsyncSession,
    *,
    org_id: Optional[int] = None,
) -> dict[str, int]:
    stmt = select(jobs_table.c.status, func.count().label("count")).group_by(jobs_table.c.status)
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    result = await session.execute(stmt)
    return {row.status: row.count for row in result}


async def job_status_timeseries(
    session: AsyncSession,
    *,
    days: int = 14,
    org_id: Optional[int] = None,
) -> list[dict[str, object]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = select(
        jobs_table.c.status,
        jobs_table.c.queued_at,
        jobs_table.c.completed_at,
        jobs_table.c.updated_at,
    ).where(jobs_table.c.updated_at >= cutoff)
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)

    result = await session.execute(stmt)
    buckets: dict[date, defaultdict[str, int]] = defaultdict(lambda: defaultdict(int))

    for row in result.mappings():
        status = row["status"]
        timestamp = row.get("completed_at") or row.get("updated_at") or row.get("queued_at")
        if timestamp is None:
            continue
        day = timestamp.astimezone(timezone.utc).date()
        buckets[day][status] += 1

    entries: list[dict[str, object]] = []
    for day in sorted(buckets):
        counts = dict(buckets[day])
        entries.append(
            {
                "date": day,
                "counts": counts,
                "total": sum(counts.values()),
            }
        )
    return entries


async def distinct_org_ids(
    session: AsyncSession,
    *,
    hours_back: Optional[int] = None,
) -> list[int]:
    stmt = select(jobs_table.c.org_id).distinct().where(jobs_table.c.org_id.isnot(None))
    if hours_back is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        stmt = stmt.where(jobs_table.c.updated_at >= cutoff)
    result = await session.execute(stmt)
    org_ids = [int(row.org_id) for row in result if row.org_id is not None]
    return sorted(set(org_ids))


async def org_job_status_counts(
    session: AsyncSession,
    *,
    org_id: Optional[int] = None,
    hours_back: Optional[int] = None,
) -> list[dict]:
    stmt = select(
        jobs_table.c.org_id,
        jobs_table.c.status,
        func.count().label("count"),
    )
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    if hours_back is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        stmt = stmt.where(jobs_table.c.updated_at >= cutoff)
    stmt = stmt.group_by(jobs_table.c.org_id, jobs_table.c.status)
    result = await session.execute(stmt)
    return [
        {
            "org_id": int(row.org_id),
            "status": row.status,
            "count": row.count,
        }
        for row in result
        if row.org_id is not None
    ]


async def org_last_activity(
    session: AsyncSession,
    *,
    org_id: Optional[int] = None,
    hours_back: Optional[int] = None,
) -> dict[int, datetime]:
    stmt = select(
        jobs_table.c.org_id,
        func.max(jobs_table.c.updated_at).label("last_updated"),
    )
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    if hours_back is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        stmt = stmt.where(jobs_table.c.updated_at >= cutoff)
    stmt = stmt.group_by(jobs_table.c.org_id)
    result = await session.execute(stmt)
    activity: dict[int, datetime] = {}
    for row in result:
        if row.org_id is None:
            continue
        activity[int(row.org_id)] = row.last_updated
    return activity


async def org_active_agents(
    session: AsyncSession,
    *,
    org_id: Optional[int] = None,
    hours_back: int = 24,
) -> dict[int, set[str]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    stmt = select(jobs_table.c.org_id, jobs_table.c.agent_id).where(
        jobs_table.c.agent_id.isnot(None),
        jobs_table.c.updated_at >= cutoff,
    )
    if org_id is not None:
        stmt = stmt.where(jobs_table.c.org_id == org_id)
    result = await session.execute(stmt)
    mapping: dict[int, set[str]] = {}
    for row in result:
        if row.org_id is None or not row.agent_id:
            continue
        bucket = mapping.setdefault(int(row.org_id), set())
        bucket.add(str(row.agent_id))
    return mapping


async def list_recent_failures(
    session: AsyncSession,
    org_id: int,
    *,
    limit: int = 10,
) -> list[dict]:
    stmt = (
        select(jobs_table)
        .where(
            jobs_table.c.org_id == org_id,
            jobs_table.c.status.in_(["failed", "cancelled"]),
        )
        .order_by(jobs_table.c.updated_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    rows = [dict(row) for row in result.mappings()]
    return _normalise_job_rows(rows)


async def get_job(session: AsyncSession, job_id: int) -> Optional[dict]:
    stmt = select(jobs_table).where(jobs_table.c.job_id == job_id).limit(1)
    result = await session.execute(stmt)
    row = result.mappings().first()
    if not row:
        return None
    payload = dict(row)
    for key in ("queued_at", "leased_at", "completed_at", "updated_at"):
        value = payload.get(key)
        if isinstance(value, datetime):
            payload[key] = value.isoformat()
    payload["repo_private"] = True if payload.get("repo_private") == "true" else False
    metadata = payload.get("metadata")
    payload["metadata"] = metadata if isinstance(metadata, dict) else {}
    return payload


async def get_agent_token_record(session: AsyncSession, agent_id: str) -> Optional[dict]:
    stmt = select(agent_credentials_table).where(agent_credentials_table.c.agent_id == agent_id)
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def rotate_agent_token(
    session: AsyncSession, agent_id: str, ttl_seconds: int
) -> int:
    existing = await get_agent_token_record(session, agent_id)
    now = datetime.now(timezone.utc)
    if existing is None:
        version = 1
        stmt = insert(agent_credentials_table).values(
            agent_id=agent_id,
            token_version=version,
            rotated_at=now,
            ttl_seconds=ttl_seconds,
        )
        await session.execute(stmt)
        return version

    version = int(existing.get("token_version", 0)) + 1
    stmt = (
        update(agent_credentials_table)
        .where(agent_credentials_table.c.agent_id == agent_id)
        .values(token_version=version, rotated_at=now, ttl_seconds=ttl_seconds)
    )
    await session.execute(stmt)
    return version


async def list_agent_credentials(session: AsyncSession) -> list[dict]:
    stmt = select(agent_credentials_table)
    result = await session.execute(stmt)
    rows = []
    for row in result.mappings():
        rows.append(dict(row))
    return rows


async def record_agent_token_audit(
    session: AsyncSession,
    *,
    agent_id: str,
    rotated_by: str,
    token_version: int,
    ttl_seconds: int,
) -> None:
    now = datetime.now(timezone.utc)
    stmt = insert(agent_token_audit_table).values(
        agent_id=agent_id,
        rotated_by=rotated_by,
        token_version=token_version,
        rotated_at=now,
        ttl_seconds=ttl_seconds,
    )
    await session.execute(stmt)


async def list_agent_token_audit(session: AsyncSession, limit: int = 50) -> list[dict]:
    stmt = (
        select(agent_token_audit_table)
        .order_by(agent_token_audit_table.c.rotated_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]


async def allocate_ssh_port(
    session: AsyncSession,
    *,
    agent_id: str,
    port_start: int,
    port_end: int,
) -> Optional[int]:
    """
    Allocate a port for SSH session. Scoped per agent to avoid global conflicts.
    Excludes ports from active/pending sessions that haven't expired.
    """
    now = datetime.now(timezone.utc)
    stmt = select(ssh_sessions_table.c.host_port).where(
        and_(
            ssh_sessions_table.c.agent_id == agent_id,
            ssh_sessions_table.c.status.in_(["pending", "active"]),
            ssh_sessions_table.c.expires_at > now,
        )
    )
    result = await session.execute(stmt)
    in_use = {row.host_port for row in result}
    for port in range(port_start, port_end + 1):
        if port not in in_use:
            return port
    return None


async def create_ssh_session(
    session: AsyncSession,
    *,
    session_id: str,
    job_id: int,
    agent_id: str,
    host_port: int,
    token: str,
    authorized_user: str,
    ttl_seconds: int,
) -> dict:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)
    stmt = insert(ssh_sessions_table).values(
        session_id=session_id,
        job_id=job_id,
        agent_id=agent_id,
        host_port=host_port,
        token=token,
        authorized_user=authorized_user,
        status="pending",
        vm_ip=None,
        reason=None,
        created_at=now,
        expires_at=expires_at,
        updated_at=now,
    )
    await session.execute(stmt)
    return {
        "session_id": session_id,
        "job_id": job_id,
        "agent_id": agent_id,
        "host_port": host_port,
        "token": token,
        "authorized_user": authorized_user,
        "status": "pending",
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "vm_ip": None,
        "reason": None,
    }


async def list_agent_pending_ssh_sessions(session: AsyncSession, agent_id: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    stmt = select(ssh_sessions_table).where(
        and_(
            ssh_sessions_table.c.agent_id == agent_id,
            ssh_sessions_table.c.status == "pending",
            ssh_sessions_table.c.expires_at > now,
        )
    )
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]


async def get_ssh_session(session: AsyncSession, session_id: str) -> Optional[dict]:
    stmt = select(ssh_sessions_table).where(ssh_sessions_table.c.session_id == session_id).limit(1)
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def update_ssh_session(
    session: AsyncSession,
    session_id: str,
    *,
    status: Optional[str] = None,
    vm_ip: Optional[str] = None,
    reason: Optional[str] = None,
) -> Optional[dict]:
    values: dict = {"updated_at": datetime.now(timezone.utc)}
    if status is not None:
        values["status"] = status
        if status in {"closed", "failed", "expired"}:
            values["token"] = ""
    if vm_ip is not None:
        values["vm_ip"] = vm_ip
    if reason is not None:
        values["reason"] = reason
    stmt = (
        update(ssh_sessions_table)
        .where(ssh_sessions_table.c.session_id == session_id)
        .values(**values)
        .returning(ssh_sessions_table)
    )
    result = await session.execute(stmt)
    row = result.mappings().first()
    return dict(row) if row else None


async def list_ssh_sessions(session: AsyncSession, *, limit: int = 100) -> list[dict]:
    stmt = (
        select(ssh_sessions_table)
        .order_by(ssh_sessions_table.c.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return [dict(row) for row in result.mappings()]


async def expire_stale_ssh_sessions(session: AsyncSession) -> int:
    """
    Mark expired SSH sessions as closed and return count.
    Should be run periodically (e.g., every minute).
    """
    now = datetime.now(timezone.utc)
    stmt = (
        update(ssh_sessions_table)
        .where(
            and_(
                ssh_sessions_table.c.status.in_(["pending", "active"]),
                ssh_sessions_table.c.expires_at <= now,
            )
        )
        .values(
            status="expired",
            reason="TTL exceeded",
            updated_at=now,
            token="",
        )
    )
    result = await session.execute(stmt)
    return result.rowcount


async def try_acquire_job_lease(
    session: AsyncSession, job_id: int, agent_id: str, ttl_seconds: int
) -> Optional[int]:
    """
    Attempt to acquire a lease on a job. Returns the fence token (version) if successful, None if already leased.
    Uses CAS approach: try to update expired lease or insert new lease.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    # Try to update an expired lease
    stmt = (
        update(job_leases_table)
        .where(
            and_(
                job_leases_table.c.job_id == job_id,
                job_leases_table.c.lease_expires_at <= now,
            )
        )
        .values(
            agent_id=agent_id,
            version=job_leases_table.c.version + 1,
            lease_expires_at=expires_at,
            heartbeat_at=now,
            updated_at=now,
        )
        .returning(job_leases_table.c.version)
    )
    result = await session.execute(stmt)
    row = result.first()
    if row:
        return int(row[0])

    # No expired lease found, try to insert a new one
    try:
        stmt = (
            insert(job_leases_table)
            .values(
                job_id=job_id,
                agent_id=agent_id,
                version=1,
                lease_expires_at=expires_at,
                heartbeat_at=now,
                created_at=now,
                updated_at=now,
            )
            .returning(job_leases_table.c.version)
        )
        result = await session.execute(stmt)
        row = result.first()
        if row:
            return int(row[0])
    except Exception as exc:
        # Race condition: another agent acquired the lease between our UPDATE and INSERT
        # This is expected during concurrent lease attempts on the same job
        logger = structlog.get_logger("nimbus.control_plane.db")
        logger.debug("Lease acquisition race condition", job_id=job_id, agent_id=agent_id, error=str(exc))
        return None
    return None


async def renew_job_lease(
    session: AsyncSession, job_id: int, agent_id: str, fence_token: int, ttl_seconds: int
) -> bool:
    """Renew a job lease if the fence token matches and lease hasn't expired."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    stmt = (
        update(job_leases_table)
        .where(
            and_(
                job_leases_table.c.job_id == job_id,
                job_leases_table.c.agent_id == agent_id,
                job_leases_table.c.version == fence_token,
                job_leases_table.c.lease_expires_at > now,
            )
        )
        .values(
            lease_expires_at=expires_at,
            heartbeat_at=now,
            updated_at=now,
        )
    )
    result = await session.execute(stmt)
    return result.rowcount == 1


async def validate_lease_fence(
    session: AsyncSession, job_id: int, agent_id: str, fence_token: int
) -> bool:
    """Check if a fence token is valid for the given job and agent."""
    now = datetime.now(timezone.utc)
    stmt = select(
        job_leases_table.c.version,
        job_leases_table.c.agent_id,
        job_leases_table.c.lease_expires_at,
    ).where(job_leases_table.c.job_id == job_id)
    result = await session.execute(stmt)
    row = result.first()
    if not row:
        return False
    expires_at = row.lease_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return (
        row.version == fence_token
        and row.agent_id == agent_id
        and expires_at > now
    )


async def release_job_lease(
    session: AsyncSession, job_id: int, agent_id: str, fence_token: int
) -> bool:
    """Release a job lease if the fence token matches."""
    from sqlalchemy import delete

    stmt = delete(job_leases_table).where(
        and_(
            job_leases_table.c.job_id == job_id,
            job_leases_table.c.agent_id == agent_id,
            job_leases_table.c.version == fence_token,
        )
    )
    result = await session.execute(stmt)
    return result.rowcount == 1
