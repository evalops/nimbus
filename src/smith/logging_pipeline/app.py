"""Logging ingestion API for Smith."""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from typing import Iterable, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
import structlog

from ..common.schemas import LogIngestRequest
from ..common.settings import LoggingIngestSettings
from ..common.metrics import GLOBAL_REGISTRY, Counter, Histogram
from ..common.observability import configure_logging, configure_tracing, instrument_fastapi_app
INGEST_REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_ingest_requests_total", "Total log ingest requests"))
INGESTED_ROWS_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_rows_ingested_total", "Rows ingested into ClickHouse"))
DROPPED_ROWS_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_rows_dropped_total", "Log rows dropped due to size limits"))
BATCH_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_batches_total", "Batches flushed to ClickHouse"))
BATCH_BYTES_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_batch_bytes_total", "Bytes sent to ClickHouse"))
CLICKHOUSE_ERRORS_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_clickhouse_errors_total", "ClickHouse request errors"))
QUERY_REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_query_requests_total", "Log query requests"))
QUERY_ERRORS_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_logging_query_errors_total", "Log query failures"))
BATCH_LATENCY_HISTOGRAM = GLOBAL_REGISTRY.register(
    Histogram(
        "smith_logging_batch_latency_seconds",
        buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
        description="Latency of ClickHouse batch writes",
    )
)

LOGGER = structlog.get_logger("smith.logging_pipeline")

MAX_ROWS_PER_BATCH = 500
MAX_BYTES_PER_BATCH = 4 * 1024 * 1024  # 4 MiB


class PipelineState:
    def __init__(self, settings: LoggingIngestSettings, http_client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.http = http_client
        self._auth = None
        if settings.clickhouse_username and settings.clickhouse_password:
            self._auth = httpx.BasicAuth(settings.clickhouse_username, settings.clickhouse_password)

    async def write_batch(self, rows: Iterable[bytes]) -> None:
        data = b"\n".join(rows)
        if not data:
            return
        query = (
            f"INSERT INTO {self.settings.clickhouse_database}.{self.settings.clickhouse_table} "
            "FORMAT JSONEachRow"
        )
        start = time.perf_counter()
        response = await self.http.post(
            self.settings.clickhouse_url,
            params={"query": query},
            content=data,
            auth=self._auth,
        )
        duration = time.perf_counter() - start
        if response.is_error:
            CLICKHOUSE_ERRORS_COUNTER.inc()
            LOGGER.error(
                "ClickHouse insert failed",
                status=response.status_code,
                body=response.text[:2000],
            )
            BATCH_LATENCY_HISTOGRAM.observe(duration)
            raise HTTPException(status_code=502, detail="ClickHouse insert failed")
        BATCH_COUNTER.inc()
        BATCH_BYTES_COUNTER.inc(len(data))
        BATCH_LATENCY_HISTOGRAM.observe(duration)

    async def query_logs(
        self,
        *,
        job_id: Optional[int] = None,
        contains: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        limit = max(1, min(limit, 500))
        query_parts = [
            "SELECT job_id, ts, level, message",
            f"FROM {self.settings.clickhouse_database}.{self.settings.clickhouse_table}",
            "WHERE 1",
        ]
        params: dict[str, object] = {"limit": limit}

        if job_id is not None:
            query_parts.append("AND job_id = {job_id:UInt64}")
            params["job_id"] = job_id

        if contains:
            contains = contains.strip()
            if contains:
                query_parts.append("AND message ILIKE {contains:String}")
                params["contains"] = f"%{contains}%"

        query_parts.append("ORDER BY ts DESC")
        query_parts.append("LIMIT {limit:UInt32}")
        query_parts.append("FORMAT JSON")
        query = " \n".join(query_parts)

        query_params = {"query": query}
        for key, value in params.items():
            query_params[f"param_{key}"] = value

        response = await self.http.get(
            self.settings.clickhouse_url,
            params=query_params,
            auth=self._auth,
        )
        if response.is_error:
            CLICKHOUSE_ERRORS_COUNTER.inc()
            QUERY_ERRORS_COUNTER.inc()
            LOGGER.error(
                "ClickHouse query failed",
                status=response.status_code,
                body=response.text[:2000],
            )
            raise HTTPException(status_code=502, detail="ClickHouse query failed")

        payload = response.json()
        rows = payload.get("data", [])
        result: list[dict[str, object]] = []
        for row in rows:
            result.append(
                {
                    "job_id": row.get("job_id"),
                    "timestamp": row.get("ts"),
                    "level": row.get("level"),
                    "message": row.get("message"),
                }
            )
        return result


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = LoggingIngestSettings()
    configure_logging("smith.logging_pipeline", settings.log_level)
    configure_tracing(
        service_name="smith.logging_pipeline",
        endpoint=settings.otel_exporter_endpoint,
        headers=settings.otel_exporter_headers,
        sampler_ratio=settings.otel_sampler_ratio,
    )
    timeout = httpx.Timeout(settings.clickhouse_timeout_seconds)
    http_client = httpx.AsyncClient(timeout=timeout)
    app.state.pipeline = PipelineState(settings=settings, http_client=http_client)
    instrument_fastapi_app(app)
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
        INGEST_REQUEST_COUNTER.inc()
        entries = request.entries
        if not entries:
            return

        batch: list[bytes] = []
        batch_len = 0

        for entry in entries:
            serialized = json.dumps(entry.model_dump(mode="json"))
            encoded = serialized.encode("utf-8")
            if len(encoded) > MAX_BYTES_PER_BATCH:
                DROPPED_ROWS_COUNTER.inc()
                LOGGER.warning("Dropping oversize log entry", bytes=len(encoded))
                continue

            projected_size = batch_len + len(encoded) + (1 if batch else 0)
            if len(batch) >= MAX_ROWS_PER_BATCH or projected_size > MAX_BYTES_PER_BATCH:
                await state.write_batch(batch)
                batch = []
                batch_len = 0

            batch.append(encoded)
            batch_len += len(encoded) + (1 if len(batch) > 1 else 0)
            INGESTED_ROWS_COUNTER.inc()

        if batch:
            await state.write_batch(batch)

    @app.get("/status", status_code=status.HTTP_200_OK)
    async def status_probe(state: PipelineState = Depends(get_state)) -> dict[str, str]:
        return {
            "clickhouse_url": str(state.settings.clickhouse_url),
            "table": f"{state.settings.clickhouse_database}.{state.settings.clickhouse_table}",
        }

    @app.get("/logs/query", status_code=status.HTTP_200_OK)
    async def query_logs_endpoint(
        job_id: Optional[int] = None,
        contains: Optional[str] = None,
        limit: int = 100,
        state: PipelineState = Depends(get_state),
    ) -> list[dict[str, object]]:
        QUERY_REQUEST_COUNTER.inc()
        return await state.query_logs(job_id=job_id, contains=contains, limit=limit)

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint() -> PlainTextResponse:
        return PlainTextResponse(GLOBAL_REGISTRY.render())

    return app
