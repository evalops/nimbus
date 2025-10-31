"""Near-runner cache service embedded in the host agent."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Optional

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
import structlog
import uvicorn

from ..common.schemas import CacheToken, JobAssignment
from ..common.security import validate_cache_scope, verify_cache_token
from ..common.settings import HostAgentSettings


LOGGER = structlog.get_logger("nimbus.host_agent.cache")


@dataclass(frozen=True)
class NearCacheBinding:
    """Metadata describing how a workload should access the near-runner cache."""

    host_endpoint: Optional[str]
    guest_endpoint: Optional[str]
    mount_tag: Optional[str]
    mount_path: Optional[str]

    def metadata_entries(self) -> dict[str, str]:
        entries: dict[str, str] = {}
        if self.host_endpoint:
            entries["cache.endpoint.host"] = self.host_endpoint
        if self.guest_endpoint:
            entries["cache.endpoint.guest"] = self.guest_endpoint
        if self.mount_tag:
            entries["cache.mount.tag"] = self.mount_tag
        if self.mount_path:
            entries["cache.mount.path"] = self.mount_path
        return entries


class NearRunnerCacheManager:
    """Orchestrates a lightweight artifact cache adjacent to the host agent."""

    def __init__(self, settings: HostAgentSettings) -> None:
        self._settings = settings
        self._enabled = bool(settings.near_runner_cache_enabled)
        self._base_dir = Path(settings.near_runner_cache_directory).expanduser().resolve()
        self._bind_host = settings.near_runner_cache_bind_address or "0.0.0.0"
        self._advertise_host = settings.near_runner_cache_advertise_host or "127.0.0.1"
        self._fallback_url = (str(settings.cache_proxy_url).rstrip("/") + "/cache/") if settings.cache_proxy_url else None
        self._mount_tag = settings.near_runner_cache_mount_tag or "nimbus-cache"
        self._mount_path = settings.near_runner_cache_mount_path or "/mnt/nimbus-cache"
        self._port = settings.near_runner_cache_port or self._allocate_port(settings)
        self._server: Optional[uvicorn.Server] = None
        self._server_task: Optional[asyncio.Task] = None
        self._app: Optional[FastAPI] = None
        self._s3_client = self._build_s3_client(settings)
        self._write_through = bool(settings.near_runner_cache_s3_write_through) if hasattr(settings, "near_runner_cache_s3_write_through") else False

    @staticmethod
    def _allocate_port(settings: HostAgentSettings) -> int:
        start = getattr(settings, "near_runner_cache_port_start", None) or 38000
        end = getattr(settings, "near_runner_cache_port_end", None) or 39000
        if start >= end:
            return start
        return random.randint(start, end)

    @staticmethod
    def _build_s3_client(settings: HostAgentSettings):
        bucket = getattr(settings, "near_runner_cache_s3_bucket", None)
        if not bucket:
            return None
        session = boto3.session.Session()
        client_kwargs = {
            "endpoint_url": getattr(settings, "near_runner_cache_s3_endpoint", None),
            "region_name": getattr(settings, "near_runner_cache_s3_region", None),
        }
        return session.client("s3", **{k: v for k, v in client_kwargs.items() if v})

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def port(self) -> Optional[int]:
        if not self._enabled:
            return None
        return self._port

    def host_endpoint(self) -> Optional[str]:
        if not self._enabled or not self._port:
            return None
        return f"http://{self._advertise_host}:{self._port}/cache/"

    def guest_endpoint(self, host_ip: str | None) -> Optional[str]:
        if not self._enabled or not self._port or not host_ip:
            return None
        return f"http://{host_ip}:{self._port}/cache/"

    def fallback_endpoint(self) -> Optional[str]:
        return self._fallback_url

    async def start(self) -> None:
        if not self._enabled or self._server_task:
            return
        self._base_dir.mkdir(parents=True, exist_ok=True)
        app = FastAPI()
        state = _CacheState(
            storage_dir=self._base_dir,
            shared_secret=self._settings.cache_shared_secret.get_secret_value(),
            s3_client=self._s3_client,
            s3_bucket=getattr(self._settings, "near_runner_cache_s3_bucket", None),
            write_through=self._write_through,
        )
        app.state.cache_state = state  # type: ignore[attr-defined]

        @app.put("/cache/{cache_key:path}", status_code=status.HTTP_201_CREATED)
        async def put_cache(
            cache_key: str,
            request: Request,
            token: CacheToken = Depends(_require_cache_token),
        ) -> Response:
            _enforce_scope(token, cache_key, "push")
            await state.write(token.organization_id, cache_key, request.stream())
            return Response(status_code=status.HTTP_201_CREATED)

        @app.get("/cache/{cache_key:path}")
        async def get_cache(
            cache_key: str,
            token: CacheToken = Depends(_require_cache_token),
        ) -> StreamingResponse:
            _enforce_scope(token, cache_key, "pull")
            data = await state.read(token.organization_id, cache_key)
            return StreamingResponse(_iter_bytes(data), media_type="application/octet-stream")

        @app.head("/cache/{cache_key:path}")
        async def head_cache(
            cache_key: str,
            token: CacheToken = Depends(_require_cache_token),
        ) -> Response:
            _enforce_scope(token, cache_key, "pull")
            size = await state.size(token.organization_id, cache_key)
            response = Response(status_code=status.HTTP_200_OK)
            response.headers["Content-Length"] = str(size)
            return response

        config = uvicorn.Config(
            app,
            host=self._bind_host,
            port=self._port,
            log_config=None,
            log_level="info",
            lifespan="off",
        )
        self._app = app
        self._server = uvicorn.Server(config)
        self._server_task = asyncio.create_task(self._serve())
        await self._server.started.wait()
        LOGGER.info("Near-runner cache service listening", host=self._bind_host, port=self._port)

    async def _serve(self) -> None:
        assert self._server is not None
        await self._server.serve()

    async def stop(self) -> None:
        if not self._enabled or not self._server:
            return
        assert self._server_task is not None
        self._server.should_exit = True
        await self._server_task
        self._server_task = None
        self._server = None
        LOGGER.info("Near-runner cache service stopped")

    async def wait_ready(self, timeout: float = 5.0) -> None:
        if not self._enabled or not self._server:
            return
        try:
            await asyncio.wait_for(self._server.started.wait(), timeout=timeout)
        except asyncio.TimeoutError as exc:  # pragma: no cover - defensive
            raise RuntimeError("Near-runner cache failed to start") from exc

    def binding_for(self, assignment: JobAssignment, host_ip: str | None) -> NearCacheBinding:
        if not self._enabled:
            return NearCacheBinding(None, None, None, None)
        host_endpoint = self.host_endpoint()
        guest_endpoint = self.guest_endpoint(host_ip)
        return NearCacheBinding(
            host_endpoint=host_endpoint,
            guest_endpoint=guest_endpoint,
            mount_tag=self._mount_tag,
            mount_path=self._mount_path,
        )

    def mount_source(self) -> Optional[Path]:
        if not self._enabled:
            return None
        return self._base_dir

    def register_started(self) -> None:
        # Backwards compatibility shim; no-op.
        return


def _iter_bytes(data: bytes) -> AsyncIterator[bytes]:
    async def _generator():
        yield data

    return _generator()


def _require_cache_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    request: Request | None = None,
) -> CacheToken:
    app = request.app if request else None  # type: ignore[attr-defined]
    state: _CacheState = getattr(app.state, "cache_state")  # type: ignore[attr-defined]
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing cache token")
    token_value = authorization.split(" ", 1)[1]
    cache_token = verify_cache_token(state.shared_secret, token_value)
    if cache_token is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid cache token")
    return cache_token


def _enforce_scope(token: CacheToken, cache_key: str, operation: str) -> None:
    org_id = token.organization_id
    if not validate_cache_scope(token, "push" if operation == "push" else "pull", org_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks required scope")


class _CacheState:
    def __init__(
        self,
        *,
        storage_dir: Path,
        shared_secret: str,
        s3_client,
        s3_bucket: Optional[str],
        write_through: bool,
    ) -> None:
        self.storage_dir = storage_dir
        self.shared_secret = shared_secret
        self.s3_client = s3_client
        self.s3_bucket = s3_bucket
        self.write_through = write_through

    def _namespaced(self, org_id: int, cache_key: str) -> Path:
        sanitized = cache_key.strip().lstrip("/")
        if ".." in sanitized:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cache key")
        return self.storage_dir / f"org-{org_id}" / sanitized

    def _s3_key(self, org_id: int, cache_key: str) -> Optional[str]:
        if not self.s3_client or not self.s3_bucket:
            return None
        sanitized = cache_key.strip().lstrip("/")
        return f"org-{org_id}/{sanitized}"

    async def write(self, org_id: int, cache_key: str, data_iter: AsyncIterator[bytes]) -> None:
        path = self._namespaced(org_id, cache_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with path.open("wb") as handle:
            async for chunk in data_iter:
                handle.write(chunk)
                size += len(chunk)
        LOGGER.debug("cache_write", org_id=org_id, key=cache_key, bytes=size)
        if self.write_through and self.s3_client and self.s3_bucket:
            key = self._s3_key(org_id, cache_key)
            if key:
                await asyncio.to_thread(self.s3_client.upload_file, str(path), self.s3_bucket, key)

    async def read(self, org_id: int, cache_key: str) -> bytes:
        path = self._namespaced(org_id, cache_key)
        if path.exists():
            return path.read_bytes()
        key = self._s3_key(org_id, cache_key)
        if not key:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss")
        try:
            response = await asyncio.to_thread(self.s3_client.get_object, Bucket=self.s3_bucket, Key=key)
        except self.s3_client.exceptions.NoSuchKey:  # type: ignore[attr-defined]
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from None
        body = response.get("Body")
        data = body.read() if body is not None else b""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return data

    async def size(self, org_id: int, cache_key: str) -> int:
        path = self._namespaced(org_id, cache_key)
        if path.exists():
            return path.stat().st_size
        key = self._s3_key(org_id, cache_key)
        if not key:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss")
        try:
            response = await asyncio.to_thread(self.s3_client.head_object, Bucket=self.s3_bucket, Key=key)
        except self.s3_client.exceptions.NoSuchKey:  # type: ignore[attr-defined]
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from None
        length = response.get("ContentLength")
        if length is None:
            return 0
        return int(length)
