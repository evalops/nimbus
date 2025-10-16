from __future__ import annotations

import asyncio
import hmac
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import jwt
import pytest

from nimbus.cache_proxy.app import create_app as create_cache_app
from nimbus.common.schemas import RunnerRegistrationToken
from nimbus.common.security import mint_cache_token
from nimbus.control_plane.app import create_app as create_control_app
from nimbus.logging_pipeline.app import create_app as create_logging_app


class FakeRedis:
    def __init__(self) -> None:
        self._queues: dict[str, deque[str]] = defaultdict(deque)

    async def lpush(self, key: str, value: str) -> None:
        self._queues[key].appendleft(value)

    async def rpop(self, key: str) -> Optional[str]:
        try:
            return self._queues[key].pop()
        except IndexError:
            return None

    async def llen(self, key: str) -> int:
        return len(self._queues[key])

    async def aclose(self) -> None:
        return None


class FakeGitHubAppClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        self._token = RunnerRegistrationToken(
            token="runner-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    async def create_runner_registration_token(self, repo_full_name: str) -> RunnerRegistrationToken:
        return self._token


class FakePipelineState:
    def __init__(self, settings, http_client) -> None:  # noqa: D401
        self.settings = settings
        self._entries: list[dict[str, Any]] = []

    async def write_batch(self, rows: Any) -> None:
        for row in rows:
            payload = json.loads(row.decode("utf-8"))
            self._entries.append(payload)

    async def query_logs(
        self,
        *,
        job_id: Optional[int] = None,
        contains: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        results = []
        for entry in self._entries:
            if job_id is not None and entry.get("job_id") != job_id:
                continue
            if contains and contains not in entry.get("message", ""):
                continue
            results.append(
                {
                    "job_id": entry.get("job_id"),
                    "timestamp": entry.get("timestamp"),
                    "level": entry.get("level"),
                    "message": entry.get("message"),
                }
            )
            if len(results) >= limit:
                break
        return results


def _git_signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, digestmod="sha256").hexdigest()


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
async def test_end_to_end_job_and_cache_flow(monkeypatch, tmp_path: Path) -> None:
    cache_secret = "cache-secret"
    webhook_secret = "webhook-secret"
    agent_secret = "agent-secret"

    database_url = f"sqlite+aiosqlite:///{tmp_path/'control.db'}"
    storage_path = tmp_path / "cache"
    storage_path.mkdir()

    monkeypatch.setattr("nimbus.control_plane.app.redis_from_url", lambda url, decode_responses=False: FakeRedis())
    monkeypatch.setattr("nimbus.control_plane.app.GitHubAppClient", FakeGitHubAppClient)
    monkeypatch.setattr("nimbus.logging_pipeline.app.PipelineState", FakePipelineState)

    env = {
        "NIMBUS_GITHUB_APP_ID": "1",
        "NIMBUS_GITHUB_APP_PRIVATE_KEY": "test",
        "NIMBUS_GITHUB_APP_INSTALLATION_ID": "1",
        "NIMBUS_GITHUB_WEBHOOK_SECRET": webhook_secret,
        "NIMBUS_REDIS_URL": "redis://test",
        "NIMBUS_DATABASE_URL": database_url,
        "NIMBUS_JWT_SECRET": "jwt-secret",
        "NIMBUS_PUBLIC_BASE_URL": "http://localhost",
        "NIMBUS_CACHE_TOKEN_TTL": "3600",
        "NIMBUS_CACHE_SHARED_SECRET": cache_secret,
        "NIMBUS_AGENT_TOKEN_SECRET": agent_secret,
        "NIMBUS_AGENT_TOKEN_RATE_LIMIT": "2",
        "NIMBUS_AGENT_TOKEN_RATE_INTERVAL": "60",
        "NIMBUS_CACHE_STORAGE_PATH": str(storage_path),
        "NIMBUS_CACHE_METRICS_DB": f"sqlite+pysqlite:///{(tmp_path / 'cache_metrics.db').as_posix()}",
        "NIMBUS_DOCKER_CACHE_DB_PATH": f"sqlite+pysqlite:///{(tmp_path / 'docker_metadata.db').as_posix()}",
        "NIMBUS_CLICKHOUSE_URL": "http://clickhouse",
        "NIMBUS_CLICKHOUSE_DATABASE": "nimbus",
        "NIMBUS_CLICKHOUSE_TABLE": "ci_logs",
        "NIMBUS_METRICS_TOKEN": "metrics-secret",
        "NIMBUS_CACHE_METRICS_TOKEN": "metrics-secret",
        "NIMBUS_LOGGING_METRICS_TOKEN": "metrics-secret",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    control_app = create_control_app()
    logging_app = create_logging_app()
    cache_app = create_cache_app()

    control_client: httpx.AsyncClient | None = None
    logging_client: httpx.AsyncClient | None = None
    cache_client: httpx.AsyncClient | None = None
    control_lifespan = logging_lifespan = cache_lifespan = None

    control_client, control_lifespan = await _create_client(control_app)
    logging_client, logging_lifespan = await _create_client(logging_app)
    cache_client, cache_lifespan = await _create_client(cache_app)

    try:
        metrics_headers = {"Authorization": "Bearer metrics-secret"}
        payload = {
            "action": "queued",
            "repository": {
                "id": 42,
                "name": "demo",
                "full_name": "acme/demo",
                "private": False,
                "owner_id": 7,
            },
            "workflow_job": {
                "id": 101,
                "run_id": 202,
                "run_attempt": 1,
                "status": "queued",
                "labels": ["firecracker", "nimbus"],
            },
        }
        body = json.dumps(payload).encode("utf-8")
        signature = _git_signature(webhook_secret, body)
        response = await control_client.post(
            "/webhooks/github",
            content=body,
            headers={
                "x-hub-signature-256": signature,
                "x-hub-signature-timestamp": str(int(time.time())),
                "content-type": "application/json",
            },
        )
        assert response.status_code == 202

        admin_token = jwt.encode(
            {
                "sub": "admin",
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            },
            env["NIMBUS_JWT_SECRET"],
            algorithm="HS256",
        )
        mint_response = await control_client.post(
            "/api/agents/token",
            json={"agent_id": "agent-1", "ttl_seconds": 900},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert mint_response.status_code == 200
        minted_payload = mint_response.json()
        headers = {"Authorization": f"Bearer {minted_payload['token']}"}
        lease_response = await control_client.post(
            "/api/jobs/lease",
            json={"agent_id": "agent-1", "agent_version": "0.1", "capabilities": ["firecracker"]},
            headers=headers,
        )
        assert lease_response.status_code == 200
        leased_job = lease_response.json()["job"]
        assert leased_job["job_id"] == 101

        status_response = await control_client.post(
            "/api/jobs/status",
            json={"agent_id": "agent-1", "job_id": 101, "status": "succeeded"},
            headers=headers,
        )
        assert status_response.status_code == 202

        status_payload = await control_client.get("/api/status", headers=headers)
        assert status_payload.status_code == 200
        body_json = status_payload.json()
        assert body_json["queue_length"] == 0
        assert body_json["jobs_by_status"]["succeeded"] == 1

        log_entries = {
            "entries": [
                {
                    "job_id": 101,
                    "agent_id": "agent-1",
                    "level": "info",
                    "message": "job started",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                {
                    "job_id": 101,
                    "agent_id": "agent-1",
                    "level": "info",
                    "message": "job completed",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            ]
        }
        ingest_response = await logging_client.post("/logs", json=log_entries)
        assert ingest_response.status_code == 202

        query_response = await logging_client.get("/logs/query", params={"job_id": 101})
        assert query_response.status_code == 200
        logs = query_response.json()
        assert len(logs) == 2
        assert logs[0]["message"] in {"job started", "job completed"}

        cache_token = mint_cache_token(secret=cache_secret, organization_id=1, ttl_seconds=60)
        cache_headers = {"Authorization": f"Bearer {cache_token.token}"}

        upload_response = await cache_client.put("/cache/artifacts/output.txt", content=b"hello", headers=cache_headers)
        assert upload_response.status_code == 201

        fetch_response = await cache_client.get("/cache/artifacts/output.txt", headers=cache_headers)
        assert fetch_response.status_code == 200
        assert fetch_response.content == b"hello"

        rotate_response = await control_client.post(
            "/api/agents/token",
            json={"agent_id": "agent-1", "ttl_seconds": 900},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert rotate_response.status_code == 200
        rotated_payload = rotate_response.json()

        old_headers = headers
        old_lease = await control_client.post(
            "/api/jobs/lease",
            json={"agent_id": "agent-1", "agent_version": "0.1", "capabilities": ["firecracker"]},
            headers=old_headers,
        )
        assert old_lease.status_code == 403

        new_headers = {"Authorization": f"Bearer {rotated_payload['token']}"}
        empty_lease = await control_client.post(
            "/api/jobs/lease",
            json={"agent_id": "agent-1", "agent_version": "0.1", "capabilities": ["firecracker"]},
            headers=new_headers,
        )
        assert empty_lease.status_code == 200
        assert empty_lease.json()["job"] is None

        inventory_response = await control_client.get(
            "/api/agents",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert inventory_response.status_code == 200
        token_inventory = inventory_response.json()
        agent_record = next(item for item in token_inventory if item["agent_id"] == "agent-1")
        assert agent_record["token_version"] == rotated_payload["version"]

        metrics_response = await control_client.get("/metrics", headers=metrics_headers)
        assert metrics_response.status_code == 200
        assert "nimbus_control_plane_request_latency_seconds_count" in metrics_response.text

        rate_limited = await control_client.post(
            "/api/agents/token",
            json={"agent_id": "agent-1", "ttl_seconds": 900},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert rate_limited.status_code == 429

        cache_metrics = await cache_client.get("/metrics", headers=metrics_headers)
        assert cache_metrics.status_code == 200
        assert "nimbus_cache_proxy_request_latency_seconds_count" in cache_metrics.text

        head_response = await cache_client.head("/cache/artifacts/output.txt", headers=cache_headers)
        assert head_response.status_code == 200
        assert head_response.headers["content-length"] == "5"

        metrics_control = await control_client.get("/metrics", headers=metrics_headers)
        assert "nimbus_control_plane_requests_total" in metrics_control.text

        metrics_logging = await logging_client.get("/metrics", headers=metrics_headers)
        assert "nimbus_logging_rows_ingested_total" in metrics_logging.text

        metrics_cache = await cache_client.get("/metrics", headers=metrics_headers)
        assert "nimbus_cache_hits_total" in metrics_cache.text
    finally:
        if control_client is not None:
            await control_client.aclose()
        if logging_client is not None:
            await logging_client.aclose()
        if cache_client is not None:
            await cache_client.aclose()
        if control_lifespan is not None:
            await control_lifespan.__aexit__(None, None, None)
        if logging_lifespan is not None:
            await logging_lifespan.__aexit__(None, None, None)
        if cache_lifespan is not None:
            await cache_lifespan.__aexit__(None, None, None)
