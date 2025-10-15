"""Logging ingestion API for Smith."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, status

from fastapi import Request

from ..common.schemas import LogIngestRequest
from ..common.settings import LoggingIngestSettings

LOGGER = logging.getLogger("smith.logging_pipeline")


class PipelineState:
    def __init__(self, settings: LoggingIngestSettings, http_client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.http = http_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = LoggingIngestSettings()
    http_client = httpx.AsyncClient()
    app.state.pipeline = PipelineState(settings=settings, http_client=http_client)
    try:
        yield
    finally:
        await http_client.aclose()


def get_state(request: Request) -> PipelineState:
    return request.app.state.pipeline  # type: ignore[attr-defined]


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.post("/logs", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_logs(request: LogIngestRequest, state: PipelineState = Depends(get_state)) -> None:
        if not request.entries:
            return

        settings = state.settings
        insert_query = (
            f"INSERT INTO {settings.clickhouse_database}.{settings.clickhouse_table} "
            "FORMAT JSONEachRow"
        )
        payload = "\n".join(json.dumps(entry.model_dump()) for entry in request.entries)

        auth = None
        if settings.clickhouse_username and settings.clickhouse_password:
            auth = httpx.BasicAuth(settings.clickhouse_username, settings.clickhouse_password)

        response = await state.http.post(
            settings.clickhouse_url,
            params={"query": insert_query},
            content=payload.encode("utf-8"),
            auth=auth,
        )
        if response.is_error:
            LOGGER.error("ClickHouse insert failed", extra={"status": response.status_code})
            raise HTTPException(status_code=502, detail="ClickHouse insert failed")

    return app
