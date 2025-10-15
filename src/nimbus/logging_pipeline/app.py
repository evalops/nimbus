"""Logging ingestion API for Nimbus."""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from typing import Iterable, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
import structlog
from opentelemetry import trace

from ..common.schemas import CacheToken, LogIngestRequest
from ..common.security import verify_cache_token, validate_cache_scope
from ..common.settings import LoggingIngestSettings
from ..common.metrics import GLOBAL_REGISTRY, Counter, Histogram
from ..common.observability import configure_logging, configure_tracing, instrument_fastapi_app
INGEST_REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_ingest_requests_total", "Total log ingest requests"))
INGESTED_ROWS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_rows_ingested_total", "Rows ingested into ClickHouse"))
DROPPED_ROWS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_rows_dropped_total", "Log rows dropped due to size limits"))
BATCH_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_batches_total", "Batches flushed to ClickHouse"))
BATCH_BYTES_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_batch_bytes_total", "Bytes sent to ClickHouse"))
CLICKHOUSE_ERRORS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_clickhouse_errors_total", "ClickHouse request errors"))
QUERY_REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_query_requests_total", "Log query requests"))
QUERY_ERRORS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_logging_query_errors_total", "Log query failures"))
BATCH_LATENCY_HISTOGRAM = GLOBAL_REGISTRY.register(
    Histogram(
        "nimbus_logging_batch_latency_seconds",
        buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
        description="Latency of ClickHouse batch writes",
    )
)

LOGGER = structlog.get_logger("nimbus.logging_pipeline")
TRACER = trace.get_tracer("nimbus.logging_pipeline")

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
        with TRACER.start_as_current_span("logging_pipeline.write_batch") as span:
            start = time.perf_counter()
            response = await self.http.post(
                self.settings.clickhouse_url,
                params={"query": query},
                content=data,
                auth=self._auth,
            )
            duration = time.perf_counter() - start
            rows_count = data.count(b"\n") + 1
            span.set_attribute("nimbus.batch_rows", rows_count)
            span.set_attribute("nimbus.batch_bytes", len(data))
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
            span.set_attribute("nimbus.batch_latency_seconds", duration)

    async def query_logs(
        self,
        *,
        job_id: Optional[int] = None,
        org_id: Optional[int] = None,
        repo_id: Optional[int] = None,
        contains: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        limit = max(1, min(limit, 500))
        with TRACER.start_as_current_span("logging_pipeline.query") as span:
            span.set_attribute("nimbus.query.limit", limit)
            query_parts = [
                "SELECT job_id, org_id, repo_id, ts, level, message",
                f"FROM {self.settings.clickhouse_database}.{self.settings.clickhouse_table}",
                "WHERE 1",
            ]
            params: dict[str, object] = {"limit": limit}

            if job_id is not None:
                query_parts.append("AND job_id = {job_id:UInt64}")
                params["job_id"] = job_id
                span.set_attribute("nimbus.query.job_id", job_id)
            
            if org_id is not None:
                query_parts.append("AND org_id = {org_id:UInt64}")
                params["org_id"] = org_id
                span.set_attribute("nimbus.query.org_id", org_id)
            
            if repo_id is not None:
                query_parts.append("AND repo_id = {repo_id:UInt64}")
                params["repo_id"] = repo_id
                span.set_attribute("nimbus.query.repo_id", repo_id)

            if contains:
                contains = contains.strip()
                if contains:
                    query_parts.append("AND message ILIKE {contains:String}")
                    params["contains"] = f"%{contains}%"
                    span.set_attribute("nimbus.query.contains", contains)

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
            span.set_attribute("nimbus.query.rows", len(rows))
            return [
                {
                    "job_id": row.get("job_id"),
                    "org_id": row.get("org_id"),
                    "repo_id": row.get("repo_id"),
                    "timestamp": row.get("ts"),
                    "level": row.get("level"),
                    "message": row.get("message"),
                }
                for row in rows
            ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = LoggingIngestSettings()
    configure_logging("nimbus.logging_pipeline", settings.log_level)
    configure_tracing(
        service_name="nimbus.logging_pipeline",
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


def get_settings(request: Request) -> LoggingIngestSettings:
    return request.app.state.pipeline.settings  # type: ignore[attr-defined]


def require_cache_token(
    authorization: Optional[str] = Header(None),
    settings: LoggingIngestSettings = Depends(get_settings),
) -> CacheToken:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing auth token")
    token = authorization.split(" ", 1)[1]
    cache_token = verify_cache_token(settings.shared_secret.get_secret_value(), token)
    if cache_token is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid auth token")
    return cache_token


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.post("/logs", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_logs(
        request: LogIngestRequest,
        token: CacheToken = Depends(require_cache_token),
        state: PipelineState = Depends(get_state),
    ) -> None:
        INGEST_REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("logging_pipeline.ingest") as span:
            # Validate push scope
            org_id = token.organization_id
            if not validate_cache_scope(token, "push", org_id):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token lacks push scope")
            
            entries = request.entries
            span.set_attribute("nimbus.ingest.count", len(entries))
            span.set_attribute("nimbus.org_id", org_id)
            if not entries:
                return
            
            # Validate all entries belong to the authenticated org
            for entry in entries:
                if entry.org_id is not None and entry.org_id != org_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Entry org_id mismatch: expected {org_id}, got {entry.org_id}",
                    )
                # Ensure org_id is set
                entry.org_id = org_id

            batch: list[bytes] = []
            batch_len = 0
            batches_flushed = 0

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
                    batches_flushed += 1
                    batch = []
                    batch_len = 0

                batch.append(encoded)
                batch_len += len(encoded) + (1 if len(batch) > 1 else 0)
                INGESTED_ROWS_COUNTER.inc()

            if batch:
                await state.write_batch(batch)
                batches_flushed += 1
            span.set_attribute("nimbus.ingest.batches", batches_flushed)

    @app.get("/status", status_code=status.HTTP_200_OK)
    async def status_probe(state: PipelineState = Depends(get_state)) -> dict[str, str]:
        return {
            "clickhouse_url": str(state.settings.clickhouse_url),
            "table": f"{state.settings.clickhouse_database}.{state.settings.clickhouse_table}",
        }

    @app.get("/logs/query", status_code=status.HTTP_200_OK)
    async def query_logs_endpoint(
        job_id: Optional[int] = None,
        repo_id: Optional[int] = None,
        contains: Optional[str] = None,
        limit: int = 100,
        token: CacheToken = Depends(require_cache_token),
        state: PipelineState = Depends(get_state),
    ) -> list[dict[str, object]]:
        # Validate pull scope
        org_id = token.organization_id
        if not validate_cache_scope(token, "pull", org_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token lacks pull scope")
        
        QUERY_REQUEST_COUNTER.inc()
        # Always scope queries to the authenticated org - ignore client-supplied org_id
        return await state.query_logs(
            job_id=job_id, org_id=org_id, repo_id=repo_id, contains=contains, limit=limit
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint() -> PlainTextResponse:
        return PlainTextResponse(GLOBAL_REGISTRY.render())

    return app
