from __future__ import annotations

import asyncio

import pytest

from nimbus.common.settings import LoggingIngestSettings
from nimbus.logging_pipeline.app import BATCH_LATENCY_HISTOGRAM, PipelineState


class DummyResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.is_error = status_code >= 400
        self.text = ""


class DummyClient:
    async def post(self, *args, **kwargs):  # noqa: D401
        await asyncio.sleep(0)
        return DummyResponse(status_code=200)


@pytest.mark.asyncio
async def test_write_batch_records_latency(monkeypatch):
    monkeypatch.setenv("NIMBUS_CLICKHOUSE_URL", "http://localhost:8123")

    settings = LoggingIngestSettings()
    client = DummyClient()
    state = PipelineState(settings=settings, http_client=client)  # type: ignore[arg-type]

    before = BATCH_LATENCY_HISTOGRAM._count

    await state.write_batch([b"{}"])

    assert BATCH_LATENCY_HISTOGRAM._count == before + 1
