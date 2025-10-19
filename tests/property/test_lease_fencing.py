"""Property-based tests for lease fencing logic."""

from __future__ import annotations

import tempfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st
from sqlalchemy import update

from src.nimbus.common.schemas import JobAssignment, GitHubRepository, RunnerRegistrationToken
from src.nimbus.control_plane.jobs import QUEUE_KEY, enqueue_job, lease_job_with_fence
from src.nimbus.control_plane.db import (
    metadata,
    job_leases_table,
    jobs_table,
    record_job_queued,
    create_engine,
    session_factory,
)


class FakeRedis:
    def __init__(self) -> None:
        self._lists = defaultdict(deque)

    async def lpush(self, key: str, value: str) -> None:
        self._lists[key].appendleft(value)

    async def rpop(self, key: str):
        if key not in self._lists or not self._lists[key]:
            return None
        return self._lists[key].pop()

    async def delete(self, key: str) -> None:
        self._lists.pop(key, None)


@asynccontextmanager
async def session_context():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "nimbus.db"
        engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        Session = session_factory(engine)
        async with Session() as session:
            yield session
        await engine.dispose()


async def _prepare_job(session, job_id: int, executor: str = "firecracker") -> JobAssignment:
    repo = GitHubRepository(
        id=1,
        name="repo",
        full_name="org/repo",
        private=False,
        owner_id=1,
    )
    token = RunnerRegistrationToken(
        token="token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assignment = JobAssignment(
        job_id=job_id,
        run_id=job_id,
        run_attempt=1,
        repository=repo,
        labels=["nimbus", executor],
        runner_registration=token,
        executor=executor,
    )
    await record_job_queued(session, assignment)
    await session.commit()
    return assignment


@settings(max_examples=25, deadline=None)
@given(
    st.integers(min_value=1000, max_value=1000000),
    st.integers(min_value=1, max_value=5),
)
@pytest.mark.asyncio
async def test_lease_fencing_monotonic(job_id: int, attempts: int):
    """Ensure fence tokens never decrease across acquisitions."""
    fake_redis = FakeRedis()
    async with session_context() as session:
        assignment = await _prepare_job(session, job_id)
        await enqueue_job(fake_redis, assignment)

        seen_fences: list[int] = []
        for idx in range(attempts):
            result = await lease_job_with_fence(
                fake_redis,
                session,
                agent_id=f"agent-{idx}",
                ttl_seconds=10,
                capabilities=[assignment.executor],
            )
            if result is None:
                continue
            _, fence = result
            if seen_fences:
                assert fence > seen_fences[-1]
            seen_fences.append(fence)

            # Expire lease and reset job state for next iteration
            await session.execute(
                update(job_leases_table)
                .where(job_leases_table.c.job_id == job_id)
                .values(lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
            )
            await session.execute(
                update(jobs_table)
                .where(jobs_table.c.job_id == job_id)
                .values(
                    status="queued",
                    agent_id=None,
                    leased_at=None,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await session.commit()
            await fake_redis.lpush(QUEUE_KEY, assignment.model_dump_json())

        assert seen_fences, "Expected at least one successful lease acquisition"


@settings(max_examples=10, deadline=None)
@given(
    st.sampled_from(["firecracker", "docker", "gpu"]),
    st.sampled_from(["firecracker", "docker", "gpu"]),
)
@pytest.mark.asyncio
async def test_capability_matching(job_executor: str, agent_capability: str):
    """Jobs should only lease to agents with matching capability."""
    fake_redis = FakeRedis()
    async with session_context() as session:
        assignment = await _prepare_job(session, job_id=42, executor=job_executor)
        await enqueue_job(fake_redis, assignment)

        result = await lease_job_with_fence(
            fake_redis,
            session,
            agent_id="agent-1",
            ttl_seconds=60,
            capabilities=[agent_capability],
        )

        if job_executor == agent_capability:
            assert result is not None
            leased_job, fence = result
            assert leased_job.executor == job_executor
            assert fence > 0
        else:
            assert result is None
