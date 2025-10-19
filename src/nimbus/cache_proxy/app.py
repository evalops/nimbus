"""Cache proxy service storing artifacts on local disk or S3-compatible storage."""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import AsyncIterator, Callable, Optional

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
import structlog
from opentelemetry import trace
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url

from ..common.schemas import CacheToken
from ..common.settings import CacheProxySettings
from ..common.security import verify_cache_token, validate_cache_scope
from ..common.metrics import GLOBAL_REGISTRY, Counter, Gauge, Histogram
from ..common.observability import configure_logging, configure_tracing, instrument_fastapi_app
from ..common.http_security import require_metrics_access


def sanitize_key(storage_dir: Path, cache_key: str) -> Path:
    root = storage_dir.resolve()
    candidate = root.joinpath(*cache_key.split("/"))
    resolved = candidate.resolve(strict=False)
    if not str(resolved).startswith(str(root)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cache key")
    return resolved


def directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


class CacheBackend:
    async def write(self, cache_key: str, data_iter: AsyncIterator[bytes]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def head(self, cache_key: str) -> int:
        raise NotImplementedError

    async def read(self, cache_key: str) -> bytes:
        raise NotImplementedError

    async def delete(self, cache_key: str) -> None:
        raise NotImplementedError

    def status(self) -> dict[str, object]:
        raise NotImplementedError


class CircuitBreaker:
    def __init__(self, failure_threshold: int, reset_timeout: float):
        self._failure_threshold = max(1, failure_threshold)
        self._reset_timeout = max(0.0, reset_timeout)
        self._failure_count = 0
        self._opened_at: float | None = None

    def _maybe_reset(self) -> None:
        if self._opened_at is None:
            return
        if time.monotonic() - self._opened_at >= self._reset_timeout:
            self._opened_at = None
            self._failure_count = 0

    def allow_request(self) -> bool:
        self._maybe_reset()
        return self._opened_at is None

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self._failure_threshold:
            self._opened_at = time.monotonic()

    @property
    def is_open(self) -> bool:
        self._maybe_reset()
        return self._opened_at is not None


class LocalCacheBackend(CacheBackend):
    def __init__(self, settings: CacheProxySettings):
        self._settings = settings

    async def write(self, cache_key: str, data_iter: AsyncIterator[bytes]) -> None:
        path = sanitize_key(self._settings.storage_path, cache_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as file_obj:
            async for chunk in data_iter:
                file_obj.write(chunk)

    async def head(self, cache_key: str) -> int:
        path = sanitize_key(self._settings.storage_path, cache_key)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss")
        return path.stat().st_size

    async def read(self, cache_key: str) -> bytes:
        path = sanitize_key(self._settings.storage_path, cache_key)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss")
        return path.read_bytes()

    async def delete(self, cache_key: str) -> None:
        path = sanitize_key(self._settings.storage_path, cache_key)
        if not path.exists():
            return
        path.unlink(missing_ok=True)
        root = self._settings.storage_path.resolve()
        parent = path.parent
        while parent != root and parent.exists():
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent

    def status(self) -> dict[str, object]:
        storage = self._settings.storage_path
        storage.mkdir(parents=True, exist_ok=True)
        return {
            "backend": "local",
            "storage_path": str(storage),
            "writable": storage.exists() and os.access(storage, os.W_OK),
        }


class S3CacheBackend(CacheBackend):
    def __init__(self, settings: CacheProxySettings):
        self._settings = settings
        session = boto3.session.Session()
        client_args: dict[str, Optional[str]] = {
            "endpoint_url": settings.s3_endpoint_url,
            "region_name": settings.s3_region,
        }
        self._client = session.client("s3", **{k: v for k, v in client_args.items() if v})
        self._bucket = settings.s3_bucket
        self._max_retries = max(0, settings.s3_max_retries)
        self._retry_base = max(0.0, settings.s3_retry_base_seconds)
        self._retry_max = max(self._retry_base, settings.s3_retry_max_seconds)
        self._breaker = CircuitBreaker(
            failure_threshold=max(1, settings.s3_circuit_breaker_failures),
            reset_timeout=max(0.0, settings.s3_circuit_breaker_reset_seconds),
        )

    async def write(self, cache_key: str, data_iter: AsyncIterator[bytes]) -> None:
        data = bytearray()
        async for chunk in data_iter:
            data.extend(chunk)
        await self._call_with_retry(
            self._client.put_object,
            Bucket=self._bucket,
            Key=self._sanitize_key(cache_key),
            Body=bytes(data),
        )

    async def head(self, cache_key: str) -> int:
        from botocore.exceptions import ClientError
        
        try:
            response = await self._call_with_retry(
                self._client.head_object,
                Bucket=self._bucket,
                Key=self._sanitize_key(cache_key),
            )
        except self._client.exceptions.NoSuchKey as exc:  # type: ignore[attr-defined]
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from exc
        except ClientError as exc:
            # Map S3 error codes to HTTP status
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in {"404", "NoSuchKey", "NotFound"}:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from exc
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="S3 error") from exc
        return int(response["ContentLength"])

    async def read(self, cache_key: str) -> bytes:
        from botocore.exceptions import ClientError
        
        try:
            response = await self._call_with_retry(
                self._client.get_object,
                Bucket=self._bucket,
                Key=self._sanitize_key(cache_key),
            )
        except self._client.exceptions.NoSuchKey as exc:  # type: ignore[attr-defined]
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from exc
        except ClientError as exc:
            # Map S3 error codes to HTTP status
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in {"404", "NoSuchKey", "NotFound"}:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from exc
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="S3 error") from exc
        body = response["Body"]
        return await asyncio.to_thread(body.read)

    async def delete(self, cache_key: str) -> None:
        from botocore.exceptions import ClientError

        try:
            await self._call_with_retry(
                self._client.delete_object,
                Bucket=self._bucket,
                Key=self._sanitize_key(cache_key),
            )
        except self._client.exceptions.NoSuchKey:  # type: ignore[attr-defined]
            self._breaker.record_success()
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in {"404", "NoSuchKey", "NotFound"}:
                self._breaker.record_success()
            else:
                self._breaker.record_failure()
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="S3 error",
                ) from exc

    def status(self) -> dict[str, object]:
        return {
            "backend": "s3",
            "bucket": self._bucket,
            "endpoint": self._settings.s3_endpoint_url,
            "circuit_open": self._breaker.is_open,
        }

    def _sanitize_key(self, cache_key: str) -> str:
        if ".." in cache_key:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cache key")
        return cache_key.lstrip("/")

    async def _call_with_retry(self, func: Callable[..., object], **kwargs) -> object:
        if not self._breaker.allow_request():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cache backend temporarily unavailable",
            )

        attempt = 0
        while True:
            try:
                result = await asyncio.to_thread(func, **kwargs)
                self._breaker.record_success()
                return result
            except self._client.exceptions.NoSuchKey:
                self._breaker.record_success()
                raise
            except Exception as exc:  # noqa: BLE001
                attempt += 1
                if attempt > self._max_retries:
                    self._breaker.record_failure()
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Cache backend temporarily unavailable",
                    ) from exc
                delay = min(self._retry_base * (2 ** (attempt - 1)), self._retry_max)
                if delay:
                    await asyncio.sleep(delay)


class CacheProxyState:
    def __init__(self, settings: CacheProxySettings, backend: CacheBackend, metrics):
        self.settings = settings
        self.backend = backend
        self.metrics = metrics
        self.logger = structlog.get_logger("nimbus.cache_proxy").bind(backend=backend.status().get("backend"))

    def enforce_storage_limit(self) -> None:
        max_bytes = self.settings.max_storage_bytes
        if not max_bytes:
            return
        quota = self.settings.org_storage_quota_bytes
        storage_path = self.settings.storage_path
        total = directory_size(storage_path)
        if total <= max_bytes:
            return
        self.logger.info("cache_eviction_started", total_bytes=total, max_bytes=max_bytes)
        batch_size = max(1, self.settings.cache_eviction_batch_size)
        candidates = self.metrics.oldest_entries(limit=batch_size)
        for entry in candidates:
            if total <= max_bytes:
                break
            cache_key = entry["cache_key"]
            path = sanitize_key(storage_path, cache_key)
            size = path.stat().st_size if path.exists() else 0
            if path.exists():
                path.unlink(missing_ok=True)
                if path.parent != storage_path:
                    try:
                        path.parent.rmdir()
                    except OSError:
                        pass
            self.metrics.delete(cache_key)
            if quota is not None:
                try:
                    org_prefix, _ = cache_key.split("/", 1)
                    if org_prefix.startswith("org-"):
                        org_id = int(org_prefix.split("-", 1)[1])
                        self.update_org_usage(org_id, -size)
                except (ValueError, IndexError):
                    self.logger.debug("failed_to_parse_org_from_cache_key", cache_key=cache_key)
            CACHE_EVICTIONS_COUNTER.inc()
            total -= size
            self.logger.info("cache_evicted", cache_key=cache_key, reclaimed_bytes=size)
        TOTAL_ENTRIES_GAUGE.set(float(self.metrics.total_entries()))
        self.logger.info("cache_eviction_completed", total_bytes=directory_size(storage_path))

    def update_org_usage(self, org_id: Optional[int], delta: int) -> int:
        if org_id is None or delta == 0:
            return 0
        return self.metrics.add_org_bytes(int(org_id), delta)


REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_cache_requests_total", "Total cache proxy requests"))
HIT_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_cache_hits_total", "Cache hits"))
MISS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_cache_misses_total", "Cache misses"))
BYTES_READ_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_cache_bytes_read_total", "Bytes served from cache"))
BYTES_WRITTEN_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_cache_bytes_written_total", "Bytes written to cache"))
TOTAL_ENTRIES_GAUGE = GLOBAL_REGISTRY.register(Gauge("nimbus_cache_entries", "Number of cache entries"))
CACHE_EVICTIONS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_cache_evictions_total", "Cache entries evicted to enforce limits"))
ORG_QUOTA_VIOLATIONS_COUNTER = GLOBAL_REGISTRY.register(
    Counter("nimbus_cache_org_quota_violations_total", "Cache writes rejected due to org quota"))
CACHE_LATENCY_HISTOGRAM = GLOBAL_REGISTRY.register(
    Histogram(
        "nimbus_cache_proxy_request_latency_seconds",
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0],
        description="Cache proxy request latency",
    )
)
TRACER = trace.get_tracer("nimbus.cache_proxy")


class CacheMetrics:
    def __init__(self, database_url: str):
        self._engine = self._create_engine(database_url)
        self._initialise()

    @staticmethod
    def _create_engine(database_url: str) -> Engine:
        url = make_url(database_url)
        if url.drivername.startswith("sqlite") and url.database:
            db_path = Path(url.database).expanduser()
            if not db_path.is_absolute():
                db_path = (Path.cwd() / db_path).resolve()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            url = url.set(database=db_path.as_posix())
            database_url = url.render_as_string(hide_password=False)
        return create_engine(database_url, future=True, pool_pre_ping=True)

    def _initialise(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS cache_metrics (
                        cache_key TEXT PRIMARY KEY,
                        total_hits INTEGER NOT NULL DEFAULT 0,
                        total_misses INTEGER NOT NULL DEFAULT 0,
                        total_bytes INTEGER NOT NULL DEFAULT 0,
                        last_access TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS cache_org_usage (
                        org_id INTEGER PRIMARY KEY,
                        total_bytes INTEGER NOT NULL,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )

    def record_hit(self, cache_key: str, bytes_served: int) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO cache_metrics (cache_key, total_hits, total_bytes, last_access)
                    VALUES (:cache_key, 1, :bytes_served, CURRENT_TIMESTAMP)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        total_hits = total_hits + 1,
                        total_bytes = total_bytes + :bytes_served,
                        last_access = CURRENT_TIMESTAMP
                    """
                ),
                {"cache_key": cache_key, "bytes_served": bytes_served},
            )

    def record_miss(self, cache_key: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO cache_metrics (cache_key, total_misses, last_access)
                    VALUES (:cache_key, 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        total_misses = total_misses + 1,
                        last_access = CURRENT_TIMESTAMP
                    """
                ),
                {"cache_key": cache_key},
            )

    def top_entries(self, limit: int = 10) -> list[dict[str, object]]:
        with self._engine.connect() as conn:
            result = conn.execute(
                text(
                    """
                    SELECT cache_key, total_hits, total_misses, total_bytes, last_access
                    FROM cache_metrics
                    ORDER BY total_hits DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            )
            rows = result.mappings().all()
        return [dict(row) for row in rows]

    def total_entries(self) -> int:
        with self._engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) AS count FROM cache_metrics"))
            count = result.scalar_one()
        return int(count)

    def oldest_entries(self, limit: int = 10) -> list[dict[str, object]]:
        with self._engine.connect() as conn:
            result = conn.execute(
                text(
                    """
                    SELECT cache_key, total_hits, total_misses, total_bytes, last_access
                    FROM cache_metrics
                    ORDER BY last_access ASC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            )
            rows = result.mappings().all()
        return [dict(row) for row in rows]

    def delete(self, cache_key: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(text("DELETE FROM cache_metrics WHERE cache_key = :cache_key"), {"cache_key": cache_key})

    def add_org_bytes(self, org_id: int, delta: int) -> int:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO cache_org_usage (org_id, total_bytes)
                    VALUES (:org_id, CASE WHEN :delta < 0 THEN 0 ELSE :delta END)
                    ON CONFLICT(org_id) DO UPDATE SET
                        total_bytes = CASE
                            WHEN cache_org_usage.total_bytes + :delta < 0 THEN 0
                            ELSE cache_org_usage.total_bytes + :delta
                        END,
                        updated_at = CURRENT_TIMESTAMP
                    """
                ),
                {"org_id": org_id, "delta": delta},
            )
            result = conn.execute(
                text("SELECT total_bytes FROM cache_org_usage WHERE org_id=:org_id"),
                {"org_id": org_id},
            )
            value = result.scalar_one()
        return int(value)

    def get_org_bytes(self, org_id: int) -> int:
        with self._engine.connect() as conn:
            result = conn.execute(
                text("SELECT total_bytes FROM cache_org_usage WHERE org_id=:org_id"),
                {"org_id": org_id},
            )
            row = result.fetchone()
        return int(row[0]) if row else 0


def build_backend(settings: CacheProxySettings) -> CacheBackend:
    if settings.s3_bucket:
        if not settings.s3_endpoint_url:
            raise RuntimeError("S3 configuration incomplete for cache proxy")
        return S3CacheBackend(settings)
    return LocalCacheBackend(settings)


def get_state(request: Request) -> CacheProxyState:
    return request.app.state.cache_state  # type: ignore[attr-defined]


def require_cache_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    state: CacheProxyState = Depends(get_state),
) -> CacheToken:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing cache token")
    token = authorization.split(" ", 1)[1]
    cache_token = verify_cache_token(state.settings.shared_secret.get_secret_value(), token)
    if cache_token is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid cache token")
    return cache_token


def create_app() -> FastAPI:
    settings = CacheProxySettings()
    configure_logging("nimbus.cache_proxy", settings.log_level)
    configure_tracing(
        service_name="nimbus.cache_proxy",
        endpoint=settings.otel_exporter_endpoint,
        headers=settings.otel_exporter_headers,
        sampler_ratio=settings.otel_sampler_ratio,
    )
    backend = build_backend(settings)
    metrics = CacheMetrics(settings.metrics_database_url)
    state = CacheProxyState(settings, backend, metrics)
    app = FastAPI()
    instrument_fastapi_app(app)
    app.state.cache_state = state

    @app.middleware("http")
    async def record_latency(request: Request, call_next):  # noqa: ANN001 - FastAPI middleware signature
        start = time.perf_counter()
        state = request.app.state.cache_state  # type: ignore[attr-defined]
        try:
            response = await call_next(request)
        except Exception:
            duration = time.perf_counter() - start
            CACHE_LATENCY_HISTOGRAM.observe(duration)
            state.logger.exception(
                "http_request_error",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration * 1000, 2),
            )
            raise

        duration = time.perf_counter() - start
        CACHE_LATENCY_HISTOGRAM.observe(duration)

        log_kwargs = {
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration * 1000, 2),
        }
        if response.status_code >= 500:
            state.logger.error("http_request", **log_kwargs)
        elif duration >= 1.0:
            state.logger.warning("http_request", **log_kwargs)
        else:
            state.logger.info("http_request", **log_kwargs)

        return response

    @app.put("/cache/{cache_key:path}", status_code=status.HTTP_201_CREATED)
    async def put_cache(
        cache_key: str,
        request: Request,
        state: CacheProxyState = Depends(get_state),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> Response:
        # Validate scope for push operation
        org_id = cache_token.organization_id
        if not validate_cache_scope(cache_token, "push", org_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks push scope")
        
        # Check Content-Length for size limit
        content_length = request.headers.get("content-length")
        if content_length:
            size = int(content_length)
            if size > state.settings.max_artifact_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Artifact exceeds max size: {state.settings.max_artifact_bytes} bytes",
                )
        
        # Namespace cache key by org to prevent cross-org access
        namespaced_key = f"org-{org_id}/{cache_key}"
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("cache_proxy.put", attributes={"nimbus.cache_key": namespaced_key}) as span:
            await state.backend.write(namespaced_key, request.stream())
            bytes_written = await state.backend.head(namespaced_key)
            new_total = state.update_org_usage(org_id, bytes_written)
            quota = state.settings.org_storage_quota_bytes
            if quota is not None and new_total > quota:
                state.update_org_usage(org_id, -bytes_written)
                await state.backend.delete(namespaced_key)
                state.metrics.delete(namespaced_key)
                state.logger.warning(
                    "org_quota_exceeded",
                    org_id=org_id,
                    wrote_bytes=bytes_written,
                    new_total=new_total,
                    quota=quota,
                )
                ORG_QUOTA_VIOLATIONS_COUNTER.inc()
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Org {org_id} exceeded cache quota",
                )
            state.metrics.record_hit(namespaced_key, bytes_written)
            BYTES_WRITTEN_COUNTER.inc(bytes_written)
            HIT_COUNTER.inc()
            TOTAL_ENTRIES_GAUGE.set(float(state.metrics.total_entries()))
            state.logger.info("cache_write", cache_key=namespaced_key, org_id=org_id, bytes=bytes_written)
            state.enforce_storage_limit()
            span.set_attribute("nimbus.bytes_written", bytes_written)
            span.set_attribute("nimbus.org_id", org_id)
            span.set_attribute("nimbus.org_bytes_total", new_total)
            return Response(status_code=status.HTTP_201_CREATED)

    @app.head("/cache/{cache_key:path}")
    async def head_cache(
        cache_key: str,
        state: CacheProxyState = Depends(get_state),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> Response:
        # Validate scope for pull operation
        org_id = cache_token.organization_id
        if not validate_cache_scope(cache_token, "pull", org_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks pull scope")
        
        # Namespace cache key by org
        namespaced_key = f"org-{org_id}/{cache_key}"
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("cache_proxy.head", attributes={"nimbus.cache_key": namespaced_key}) as span:
            try:
                size = await state.backend.head(namespaced_key)
                state.metrics.record_hit(namespaced_key, size)
                HIT_COUNTER.inc()
            except HTTPException as exc:
                if exc.status_code == status.HTTP_404_NOT_FOUND:
                    state.metrics.record_miss(namespaced_key)
                    MISS_COUNTER.inc()
                    state.logger.info("cache_miss", cache_key=namespaced_key, org_id=org_id)
                raise
            state.logger.info("cache_head", cache_key=namespaced_key, org_id=org_id, bytes=size)
            response = Response(status_code=status.HTTP_200_OK)
            response.headers["Content-Length"] = str(size)
            span.set_attribute("nimbus.bytes", size)
            span.set_attribute("nimbus.org_id", org_id)
            return response

    @app.get("/cache/{cache_key:path}")
    async def get_cache(
        cache_key: str,
        state: CacheProxyState = Depends(get_state),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> StreamingResponse:
        # Validate scope for pull operation
        org_id = cache_token.organization_id
        if not validate_cache_scope(cache_token, "pull", org_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks pull scope")
        
        # Namespace cache key by org
        namespaced_key = f"org-{org_id}/{cache_key}"
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("cache_proxy.get", attributes={"nimbus.cache_key": namespaced_key}) as span:
            try:
                data = await state.backend.read(namespaced_key)
                state.metrics.record_hit(namespaced_key, len(data))
                HIT_COUNTER.inc()
                BYTES_READ_COUNTER.inc(len(data))
            except HTTPException as exc:
                if exc.status_code == status.HTTP_404_NOT_FOUND:
                    state.metrics.record_miss(namespaced_key)
                    MISS_COUNTER.inc()
                    state.logger.info("cache_miss", cache_key=namespaced_key, org_id=org_id)
                raise
            state.logger.info("cache_hit", cache_key=namespaced_key, org_id=org_id, bytes=len(data))
            span.set_attribute("nimbus.bytes", len(data))
            span.set_attribute("nimbus.org_id", org_id)
            return StreamingResponse(iter([data]), media_type="application/octet-stream")

    @app.get("/status")
    async def status_probe(state: CacheProxyState = Depends(get_state)) -> JSONResponse:
        with TRACER.start_as_current_span("cache_proxy.status"):
            status_payload = state.backend.status()
            status_payload.update(
                {
                    "total_entries": state.metrics.total_entries(),
                    "top_entries": state.metrics.top_entries(),
                    "max_storage_bytes": state.settings.max_storage_bytes,
                }
            )
            stripped_entries = []
            for entry in status_payload["top_entries"]:
                cache_key = entry.get("cache_key")
                if isinstance(cache_key, str):
                    entry = dict(entry)
                    entry["cache_key"] = re.sub(r"^org-\d+/", "", cache_key)
                stripped_entries.append(entry)
            status_payload["top_entries"] = stripped_entries
            TOTAL_ENTRIES_GAUGE.set(float(status_payload["total_entries"]))
            return JSONResponse(status_payload)

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint(
        request: Request,
        state: CacheProxyState = Depends(get_state),
    ) -> PlainTextResponse:
        token = (
            state.settings.metrics_token.get_secret_value()
            if state.settings.metrics_token
            else None
        )
        require_metrics_access(request, token)
        TOTAL_ENTRIES_GAUGE.set(float(state.metrics.total_entries()))
        return PlainTextResponse(GLOBAL_REGISTRY.render())

    @app.get("/healthz", status_code=status.HTTP_200_OK)
    async def health_check(state: CacheProxyState = Depends(get_state)) -> dict:
        """Health check for K8s readiness/liveness probes."""
        health = {"status": "healthy", "checks": {}}
        
        # Check backend availability
        try:
            backend_status = state.backend.status()
            health["checks"]["backend"] = backend_status.get("backend", "unknown")
            health["checks"]["writable"] = backend_status.get("writable", False)
        except Exception as exc:
            health["checks"]["backend"] = f"error: {str(exc)}"
            health["status"] = "unhealthy"
        
        if health["status"] != "healthy":
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=health)
        
        return health

    return app
