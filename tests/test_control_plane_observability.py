from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import importlib
import jwt
import pytest
import sys
from types import ModuleType

if "nimbus.control_plane.saml" not in sys.modules:
    stub = ModuleType("nimbus.control_plane.saml")
    stub.SamlAuthenticator = type("DummySaml", (), {})  # type: ignore[attr-defined]
    stub.SamlSettings = type("DummySettings", (), {})  # type: ignore[attr-defined]
    sys.modules["nimbus.control_plane.saml"] = stub

from nimbus.control_plane import app as control_app
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
async def test_observability_orgs_summary(monkeypatch, tmp_path: Path) -> None:
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
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    monkeypatch.setattr("nimbus.control_plane.app.redis_from_url", lambda *_args, **_kwargs: FakeRedis())
    importlib.reload(control_app)
    app = control_app.create_app()
    client, lifespan = await _create_client(app)

    try:
        admin_token = jwt.encode(
            {
                "sub": "admin",
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            },
            env["NIMBUS_JWT_SECRET"],
            algorithm="HS256",
        )

        assignment = JobAssignment(
            job_id=501,
            run_id=1001,
            run_attempt=1,
            repository=GitHubRepository(
                id=77,
                name="demo",
                full_name="acme/demo",
                private=False,
                owner_id=987,
            ),
            metadata={"resource.duration_seconds": "600"},
            labels=["linux"],
            runner_registration=RunnerRegistrationToken(
                token="runner",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ),
        )

        state = app.state.container
        async with state.session_factory() as session:  # type: ignore[call-arg]
            await db.record_job_queued(session, assignment)
            await db.mark_job_leased(session, assignment.job_id, "agent-1")
            await session.commit()

        update_payload = {
            "agent_id": "agent-1",
            "job_id": assignment.job_id,
            "status": "failed",
            "message": "unit tests failed",
            "fence_token": 1,
        }
        agent_token = jwt.encode(
            {
                "agent_id": "agent-1",
                "sub": "agent-1",
                "scope": "agent",
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            },
            env["NIMBUS_AGENT_TOKEN_SECRET"],
            algorithm="HS256",
        )

        async with state.session_factory() as session:  # type: ignore[call-arg]
            token = await db.try_acquire_job_lease(session, assignment.job_id, "agent-1", ttl_seconds=60)
            await session.commit()

        update_payload["fence_token"] = token

        status_resp = await client.post(
            "/api/jobs/status",
            json=update_payload,
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        assert status_resp.status_code == 202

        resp = await client.get(
            "/api/observability/orgs",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        payload = resp.json()
        assert len(payload) == 1
        summary = payload[0]
        assert summary["org_id"] == assignment.repository.owner_id
        assert summary["status_counts"].get("failed") == 1
        assert summary["recent_failures"][0]["job_id"] == assignment.job_id

        cost_resp = await client.get(
            "/api/observability/cost",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        assert cost_resp.status_code == 200
        cost_payload = cost_resp.json()
        assert cost_payload["inputs"]["runs_per_day"] >= 1
        assert "agent-1" in summary["active_agents"]

    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)
