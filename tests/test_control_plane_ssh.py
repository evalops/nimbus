from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
import pytest

from nimbus.control_plane.app import create_app
from nimbus.control_plane import db
from nimbus.common.schemas import GitHubRepository, JobAssignment, RunnerRegistrationToken


class FakeRedis:
    def __init__(self) -> None:
        self._queues: dict[str, list[str]] = {}

    async def lpush(self, key: str, value: str) -> None:
        self._queues.setdefault(key, []).insert(0, value)

    async def rpop(self, key: str) -> str | None:
        values = self._queues.get(key)
        if not values:
            return None
        return values.pop()

    async def llen(self, key: str) -> int:
        return len(self._queues.get(key, []))

    async def aclose(self) -> None:
        return None


async def _create_client(app):
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    return client, lifespan


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio("asyncio")
async def test_admin_and_agent_manage_ssh_sessions(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path/'control.db'}"
    env = {
        "NIMBUS_GITHUB_APP_ID": "1",
        "NIMBUS_GITHUB_APP_PRIVATE_KEY": "test",
        "NIMBUS_GITHUB_APP_INSTALLATION_ID": "1",
        "NIMBUS_GITHUB_WEBHOOK_SECRET": "webhook",
        "NIMBUS_REDIS_URL": "redis://test",
        "NIMBUS_DATABASE_URL": database_url,
        "NIMBUS_JWT_SECRET": "jwt-secret",
        "NIMBUS_PUBLIC_BASE_URL": "http://localhost",
        "NIMBUS_CACHE_TOKEN_TTL": "3600",
        "NIMBUS_CACHE_SHARED_SECRET": "cache-secret",
        "NIMBUS_AGENT_TOKEN_SECRET": "agent-secret",
        "NIMBUS_AGENT_TOKEN_RATE_LIMIT": "10",
        "NIMBUS_AGENT_TOKEN_RATE_INTERVAL": "60",
        "NIMBUS_SSH_PORT_START": "23000",
        "NIMBUS_SSH_PORT_END": "23010",
        "NIMBUS_SSH_SESSION_TTL": "600",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    monkeypatch.setattr("nimbus.control_plane.app.redis_from_url", lambda url, decode_responses=False: FakeRedis())

    app = create_app()
    client, lifespan = await _create_client(app)

    try:
        state = app.state.container
        assignment = JobAssignment(
            job_id=101,
            run_id=202,
            run_attempt=1,
            repository=GitHubRepository(
                id=42,
                name="demo",
                full_name="acme/demo",
                private=False,
                owner_id=123,
            ),
            labels=["firecracker"],
            runner_registration=RunnerRegistrationToken(
                token="runner-token",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ),
        )
        async with state.session_factory() as session:  # type: ignore[call-arg]
            await db.record_job_queued(session, assignment)
            await db.mark_job_leased(session, assignment.job_id, "agent-1")
            await session.commit()

        admin_token = jwt.encode(
            {
                "sub": "admin",
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            },
            env["NIMBUS_JWT_SECRET"],
            algorithm="HS256",
        )

        create_resp = await client.post(
            "/api/ssh/sessions",
            json={"job_id": 101, "ttl_seconds": 300, "authorized_user": "runner"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert create_resp.status_code == 200
        session_payload = create_resp.json()
        session_id = session_payload["session_id"]
        assert session_payload["status"] == "pending"

        list_resp = await client.get(
            "/api/ssh/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert list_resp.status_code == 200
        assert any(entry["session_id"] == session_id for entry in list_resp.json())

        token_resp = await client.post(
            "/api/agents/token",
            json={"agent_id": "agent-1", "ttl_seconds": 900},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert token_resp.status_code == 200
        agent_token = token_resp.json()["token"]

        agent_sessions = await client.get(
            "/api/agents/ssh/sessions",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        assert agent_sessions.status_code == 200
        pending = agent_sessions.json()
        assert pending and pending[0]["session_id"] == session_id

        activate_resp = await client.post(
            f"/api/ssh/sessions/{session_id}/activate",
            json={"vm_ip": "172.31.50.2"},
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        assert activate_resp.status_code == 200
        assert activate_resp.json()["status"] == "active"

        close_resp = await client.post(
            f"/api/ssh/sessions/{session_id}/close",
            json={"reason": "completed"},
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        assert close_resp.status_code == 200
        assert close_resp.json()["status"] == "closed"

        admin_list_after = await client.get(
            "/api/ssh/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert admin_list_after.status_code == 200
        entry = next(item for item in admin_list_after.json() if item["session_id"] == session_id)
        assert entry["status"] == "closed"
        assert entry["reason"] == "completed"

    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)
