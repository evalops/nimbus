"""Tests for logging pipeline tenant scoping and quotas."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import httpx

from src.nimbus.common.settings import LoggingIngestSettings
from src.nimbus.logging_pipeline.app import PipelineState


def _auth_header(auth: httpx.Auth, method: str = "GET") -> str:
    request = httpx.Request(method, "http://example.com")
    flow = auth.auth_flow(request)
    prepared = next(flow)
    return prepared.headers["Authorization"]


@pytest.mark.asyncio
async def test_query_logs_requires_org(monkeypatch):
    monkeypatch.setenv("NIMBUS_CLICKHOUSE_URL", "http://localhost:8123")
    settings = LoggingIngestSettings()
    client = AsyncMock()
    state = PipelineState(settings=settings, http_client=client)  # type: ignore[arg-type]

    with pytest.raises(PermissionError):
        await state.query_logs()


@pytest.mark.asyncio
async def test_query_logs_enforces_limit(monkeypatch):
    monkeypatch.setenv("NIMBUS_CLICKHOUSE_URL", "http://localhost:8123")
    settings = LoggingIngestSettings()
    settings.clickhouse_query_user_template = "tenant_{org_id}"
    settings.clickhouse_query_password_template = "pw-{org_id}"
    settings.clickhouse_ingest_username = "ingest"
    settings.clickhouse_ingest_password = "ingestpw"

    async def fake_get(*args, **kwargs):
        class Response:
            is_error = False

            def json(self):
                return {"data": []}

        return Response()

    client = AsyncMock()
    client.get.side_effect = fake_get

    state = PipelineState(settings=settings, http_client=client)  # type: ignore[arg-type]

    await state.query_logs(org_id=1, limit=9999)

    params = client.get.call_args.kwargs.get("params", {})
    assert params.get("param_limit") == 500
    assert params.get("session_settings[evalops_tenant_id]") == "1"

    auth = client.get.call_args.kwargs.get("auth")
    expected = httpx.BasicAuth("tenant_1", "pw-1")
    assert _auth_header(auth) == _auth_header(expected)


@pytest.mark.asyncio
async def test_write_batch_uses_ingest_credentials(monkeypatch):
    monkeypatch.setenv("NIMBUS_CLICKHOUSE_URL", "http://localhost:8123")
    settings = LoggingIngestSettings()
    settings.clickhouse_ingest_username = "ingest"
    settings.clickhouse_ingest_password = "ingestpw"

    async def fake_post(*args, **kwargs):
        class Response:
            is_error = False

            def json(self):
                return {}

            status_code = 200
            text = ""

        return Response()

    client = AsyncMock()
    client.post.side_effect = fake_post
    state = PipelineState(settings=settings, http_client=client)  # type: ignore[arg-type]

    await state.write_batch([b"{}"])

    auth = client.post.call_args.kwargs.get("auth")
    expected = httpx.BasicAuth("ingest", "ingestpw")
    assert _auth_header(auth, "POST") == _auth_header(expected, "POST")
