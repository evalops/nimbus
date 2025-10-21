from __future__ import annotations

from unittest.mock import AsyncMock

from contextlib import asynccontextmanager

import httpx
import pytest

from nimbus.common.security import mint_cache_token
from nimbus.logging_pipeline.app import create_app as create_logging_app


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


@pytest.mark.asyncio
async def test_metadata_endpoint_writes(monkeypatch):
    monkeypatch.setenv("NIMBUS_CLICKHOUSE_URL", "http://localhost:8123")
    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", "super-secret")

    app = create_logging_app()

    mock_writer = AsyncMock(return_value=None)
    monkeypatch.setattr("nimbus.logging_pipeline.app.PipelineState.write_metadata", mock_writer, raising=False)

    token = mint_cache_token(secret="super-secret", organization_id=42, ttl_seconds=3600, scope="push:org-42")

    payload = {
        "records": [
            {
                "job_id": 1001,
                "run_id": 2002,
                "run_attempt": 1,
                "org_id": 42,
                "repo_id": 99,
                "key": "lr",
                "value": "0.05",
                "executor": "gpu",
            }
        ]
    }

    async with app_client(app) as client:
        response = await client.post(
            "/metadata/jobs",
            json=payload,
            headers={"Authorization": f"Bearer {token.token}"},
        )

    assert response.status_code == 202
    mock_writer.assert_awaited_once()


@pytest.mark.asyncio
async def test_metadata_trend_endpoint(monkeypatch):
    monkeypatch.setenv("NIMBUS_CLICKHOUSE_URL", "http://localhost:8123")
    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", "super-secret")

    app = create_logging_app()

    trend_mock = AsyncMock(return_value=[{"window_start": "2024-01-01T00:00:00Z", "total": 5}])
    monkeypatch.setattr("nimbus.logging_pipeline.app.PipelineState.metadata_trend", trend_mock, raising=False)

    token = mint_cache_token(secret="super-secret", organization_id=42, ttl_seconds=3600, scope="read:org-42")

    async with app_client(app) as client:
        response = await client.get(
            "/metadata/jobs/trends",
            params={"key": "lr"},
            headers={"Authorization": f"Bearer {token.token}"},
        )

    assert response.status_code == 200
    trend_mock.assert_awaited_once()
