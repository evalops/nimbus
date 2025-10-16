from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from nimbus.common.schemas import (
    GitHubRepository,
    JobAssignment,
    JobStatusUpdate,
    RunnerRegistrationToken,
)
from nimbus.control_plane import db


@pytest_asyncio.fixture
async def session():
    engine = db.create_engine("sqlite+aiosqlite:///:memory:")
    await db.ensure_schema(engine)
    Session = db.session_factory(engine)
    session = Session()
    try:
        yield session
    finally:
        await session.close()
        await engine.dispose()


def _make_assignment(job_id: int = 100) -> JobAssignment:
    repo = GitHubRepository(id=1, name="repo", full_name="org/repo", private=False)
    registration = RunnerRegistrationToken(token="tok", expires_at=datetime.now(timezone.utc))
    return JobAssignment(
        job_id=job_id,
        run_id=111,
        run_attempt=1,
        repository=repo,
        labels=["linux"],
        runner_registration=registration,
    )


@pytest.mark.asyncio
async def test_record_job_queued_and_list_recent_jobs(session):
    assignment = _make_assignment(200)
    await db.record_job_queued(session, assignment)
    await session.commit()

    rows = await db.list_recent_jobs(session, limit=5)
    assert rows
    row = rows[0]
    assert row["job_id"] == 200
    assert row["repo_private"] is False


@pytest.mark.asyncio
async def test_mark_job_leased_transitions(session):
    assignment = _make_assignment(201)
    await db.record_job_queued(session, assignment)
    await session.commit()

    first = await db.mark_job_leased(session, 201, "agent-1")
    await session.commit()
    assert first is True

    second = await db.mark_job_leased(session, 201, "agent-1")
    assert second is False


@pytest.mark.asyncio
async def test_record_status_update_terminal_releases(session, monkeypatch):
    assignment = _make_assignment(202)
    await db.record_job_queued(session, assignment)
    await db.mark_job_leased(session, 202, "agent-9")
    await session.commit()

    mock_release = AsyncMock(return_value=True)
    monkeypatch.setattr(db, "release_job_lease", mock_release)

    update_payload = JobStatusUpdate(
        agent_id="agent-9",
        job_id=202,
        status="succeeded",
        message="done",
        fence_token=2,
    )
    await db.record_status_update(session, update_payload)
    await session.commit()

    job_row = await db.get_job(session, 202)
    assert job_row["status"] == "succeeded"
    assert job_row["completed_at"] is not None
    mock_release.assert_awaited_once_with(session, 202, "agent-9", 2)


@pytest.mark.asyncio
async def test_rotate_agent_token_and_audit(session):
    version1 = await db.rotate_agent_token(session, "agent-10", ttl_seconds=600)
    version2 = await db.rotate_agent_token(session, "agent-10", ttl_seconds=600)
    await db.record_agent_token_audit(
        session,
        agent_id="agent-10",
        rotated_by="admin",
        token_version=version2,
        ttl_seconds=600,
    )
    await session.commit()

    records = await db.list_agent_credentials(session)
    assert records[0]["token_version"] == version2

    audit = await db.list_agent_token_audit(session, limit=10)
    assert audit[0]["agent_id"] == "agent-10"


@pytest.mark.asyncio
async def test_allocate_and_manage_ssh_sessions(session):
    port = await db.allocate_ssh_port(session, agent_id="agent-x", port_start=6000, port_end=6002)
    assert port == 6000

    session_info = await db.create_ssh_session(
        session,
        session_id="sess-1",
        job_id=1,
        agent_id="agent-x",
        host_port=port,
        authorized_user="alice",
        ttl_seconds=60,
    )
    await session.commit()
    assert session_info["status"] == "pending"

    next_port = await db.allocate_ssh_port(session, agent_id="agent-x", port_start=6000, port_end=6002)
    assert next_port == 6001

    # Expire the session and ensure allocator frees it
    await db.expire_stale_ssh_sessions(session)
    await session.commit()

    # Manually mark expired to simulate TTL passing
    await db.update_ssh_session(session, "sess-1", status="expired", reason="timeout")
    await session.commit()

    freed_port = await db.allocate_ssh_port(session, agent_id="agent-x", port_start=6000, port_end=6002)
    assert freed_port == 6000


@pytest.mark.asyncio
async def test_try_acquire_and_release_job_lease(session, monkeypatch):
    assignment = _make_assignment(303)
    await db.record_job_queued(session, assignment)
    await session.commit()

    token = await db.try_acquire_job_lease(session, 303, "agent-z", ttl_seconds=30)
    await session.commit()
    assert token == 1

    class NaiveDatetime:
        @staticmethod
        def now(tz=None):  # noqa: ANN001
            if tz is None:
                return datetime.now(timezone.utc)
            return datetime.now(tz)

    monkeypatch.setattr(db, "datetime", NaiveDatetime)

    valid = await db.validate_lease_fence(session, 303, "agent-z", token)
    assert valid is True

    renewed = await db.renew_job_lease(session, 303, "agent-z", token, ttl_seconds=60)
    assert renewed is True

    released = await db.release_job_lease(session, 303, "agent-z", token)
    assert released is True

    valid_after = await db.validate_lease_fence(session, 303, "agent-z", token)
    assert valid_after is False
