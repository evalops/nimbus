"""Tests for logging pipeline tenant scoping and quotas."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.nimbus.common.settings import LoggingIngestSettings
from src.nimbus.logging_pipeline.app import PipelineState


@pytest.mark.asyncio
async def test_query_logs_requires_org_or_job(monkeypatch):
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
