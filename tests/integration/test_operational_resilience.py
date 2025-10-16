from __future__ import annotations

import re
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest

from nimbus.cache_proxy.app import create_app as create_cache_app
from nimbus.common.security import mint_cache_token
from nimbus.logging_pipeline.app import create_app as create_logging_app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@asynccontextmanager
async def app_client(app):
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client
    finally:
        await lifespan.__aexit__(None, None, None)


@pytest.mark.anyio("asyncio")
async def test_cache_status_reports_cold_entries(monkeypatch, tmp_path: Path):
    storage = tmp_path / "cache"
    metrics_db = tmp_path / "metrics.db"
    storage.mkdir()

    env = {
        "NIMBUS_CACHE_STORAGE_PATH": str(storage),
        "NIMBUS_CACHE_SHARED_SECRET": "local-cache-secret",
        "NIMBUS_CACHE_METRICS_DB": str(metrics_db),
        "NIMBUS_CACHE_METRICS_TOKEN": "metrics-secret",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    app = create_cache_app()
    async with app_client(app) as client:
        token = mint_cache_token(secret="local-cache-secret", organization_id=1, ttl_seconds=60)
        headers = {"Authorization": f"Bearer {token.token}"}
        metrics_headers = {"Authorization": "Bearer metrics-secret"}

        put_response = await client.put("/cache/hot/item", content=b"payload", headers=headers)
        assert put_response.status_code == 201

        hit_response = await client.get("/cache/hot/item", headers=headers)
        assert hit_response.status_code == 200

        miss_response = await client.get("/cache/cold/item", headers=headers)
        assert miss_response.status_code == 404

        status_response = await client.get("/status")
        assert status_response.status_code == 200
        payload = status_response.json()
        entries = {entry["cache_key"]: entry for entry in payload["top_entries"]}

        assert payload["total_entries"] == 2
        assert entries["hot/item"]["total_hits"] >= 1
        assert entries["cold/item"]["total_hits"] == 0
        assert entries["cold/item"]["total_misses"] >= 1


@pytest.mark.anyio("asyncio")
async def test_cache_latency_histogram_accumulates(monkeypatch, tmp_path: Path):
    storage = tmp_path / "cache"
    metrics_db = tmp_path / "metrics.db"
    storage.mkdir()

    env = {
        "NIMBUS_CACHE_STORAGE_PATH": str(storage),
        "NIMBUS_CACHE_SHARED_SECRET": "local-cache-secret",
        "NIMBUS_CACHE_METRICS_DB": str(metrics_db),
        "NIMBUS_CACHE_METRICS_TOKEN": "metrics-secret",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    app = create_cache_app()
    async with app_client(app) as client:
        token = mint_cache_token(secret="local-cache-secret", organization_id=1, ttl_seconds=60)
        headers = {"Authorization": f"Bearer {token.token}"}
        metrics_headers = {"Authorization": "Bearer metrics-secret"}

        for idx in range(20):
            path = f"/cache/key-{idx}"
            await client.put(path, content=b"payload", headers=headers)
            await client.get(path, headers=headers)

        metrics_response = await client.get("/metrics", headers=metrics_headers)
        assert metrics_response.status_code == 200
        metrics_text = metrics_response.text
        assert "nimbus_cache_proxy_request_latency_seconds_count" in metrics_text
        match = re.search(r"nimbus_cache_proxy_request_latency_seconds_count (\d+)", metrics_text)
        assert match and int(match.group(1)) >= 40


@pytest.mark.anyio("asyncio")
async def test_cache_eviction_respects_limit(monkeypatch, tmp_path: Path):
    storage = tmp_path / "cache"
    metrics_db = tmp_path / "metrics.db"
    storage.mkdir()

    env = {
        "NIMBUS_CACHE_STORAGE_PATH": str(storage),
        "NIMBUS_CACHE_SHARED_SECRET": "local-cache-secret",
        "NIMBUS_CACHE_METRICS_DB": str(metrics_db),
        "NIMBUS_CACHE_MAX_BYTES": "40",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    app = create_cache_app()
    async with app_client(app) as client:
        token = mint_cache_token(secret="local-cache-secret", organization_id=1, ttl_seconds=60)
        headers = {"Authorization": f"Bearer {token.token}"}

        await client.put("/cache/old", content=b"abcdefghij", headers=headers)
        await client.get("/cache/old", headers=headers)

        await client.put("/cache/new", content=b"x" * 32, headers=headers)

        old_response = await client.get("/cache/old", headers=headers)
        assert old_response.status_code == 404

        new_response = await client.get("/cache/new", headers=headers)
        assert new_response.status_code == 200

        size = sum(p.stat().st_size for p in storage.rglob("*") if p.is_file())
        assert size <= 40

class DummyResponse:
    def __init__(self, status_code: int, text: str = "", json_data: dict | None = None):
        self.status_code = status_code
        self._text = text
        self._json = json_data or {}

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    @property
    def text(self) -> str:
        return self._text

    def json(self) -> dict:
        return self._json


class FailingAsyncClient:
    def __init__(self) -> None:
        self.post_calls = 0

    async def post(self, *args, **kwargs):  # noqa: D401
        self.post_calls += 1
        return DummyResponse(status_code=500, text="clickhouse unavailable")

    async def get(self, *args, **kwargs):  # noqa: D401
        return DummyResponse(status_code=200, json_data={"data": []})

    async def aclose(self) -> None:  # noqa: D401
        return None


@pytest.mark.anyio("asyncio")
async def test_logging_ingest_handles_clickhouse_failures(monkeypatch, tmp_path: Path):
    env = {
        "NIMBUS_CLICKHOUSE_URL": "http://clickhouse:8123",
        "NIMBUS_CLICKHOUSE_DATABASE": "nimbus",
        "NIMBUS_CLICKHOUSE_TABLE": "ci_logs",
        "NIMBUS_LOG_LEVEL": "INFO",
        "NIMBUS_LOGGING_METRICS_TOKEN": "metrics-secret",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    failing_client = FailingAsyncClient()
    original_async_client = httpx.AsyncClient

    def async_client_factory(*args, **kwargs):
        if "transport" in kwargs:
            return original_async_client(*args, **kwargs)
        return failing_client

    monkeypatch.setattr("nimbus.logging_pipeline.app.httpx.AsyncClient", async_client_factory)

    app = create_logging_app()
    async with app_client(app) as client:
        metrics_headers = {"Authorization": "Bearer metrics-secret"}
        payload = {
            "entries": [
                {
                    "job_id": 1,
                    "agent_id": "agent-1",
                    "level": "info",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "message": "hello",
                }
            ]
        }
        ingest_response = await client.post("/logs", json=payload)
        assert ingest_response.status_code == 502

        metrics_response = await client.get("/metrics", headers=metrics_headers)
        assert metrics_response.status_code == 200
        metrics_text = metrics_response.text

        error_match = re.search(r"nimbus_logging_clickhouse_errors_total (\d+)", metrics_text)
        assert error_match and int(error_match.group(1)) >= 1

        latency_match = re.search(r"nimbus_logging_batch_latency_seconds_count (\d+)", metrics_text)
        assert latency_match and int(latency_match.group(1)) >= 1
