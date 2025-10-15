"""Cache proxy service storing artifacts on local disk or S3-compatible storage."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import AsyncIterator, Optional

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from ..common.schemas import CacheToken
from ..common.settings import CacheProxySettings
from ..common.security import verify_cache_token


def sanitize_key(storage_dir: Path, cache_key: str) -> Path:
    root = storage_dir.resolve()
    candidate = root.joinpath(*cache_key.split("/"))
    resolved = candidate.resolve(strict=False)
    if not str(resolved).startswith(str(root)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cache key")
    return resolved


class CacheBackend:
    async def write(self, cache_key: str, data_iter: AsyncIterator[bytes]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def head(self, cache_key: str) -> int:
        raise NotImplementedError

    async def read(self, cache_key: str) -> bytes:
        raise NotImplementedError

    def status(self) -> dict[str, object]:
        raise NotImplementedError


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

    async def write(self, cache_key: str, data_iter: AsyncIterator[bytes]) -> None:
        data = bytearray()
        async for chunk in data_iter:
            data.extend(chunk)
        await asyncio.to_thread(
            self._client.put_object,
            Bucket=self._bucket,
            Key=self._sanitize_key(cache_key),
            Body=bytes(data),
        )

    async def head(self, cache_key: str) -> int:
        try:
            response = await asyncio.to_thread(
                self._client.head_object,
                Bucket=self._bucket,
                Key=self._sanitize_key(cache_key),
            )
        except self._client.exceptions.NoSuchKey as exc:  # type: ignore[attr-defined]
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from exc
        return int(response["ContentLength"])

    async def read(self, cache_key: str) -> bytes:
        try:
            response = await asyncio.to_thread(
                self._client.get_object,
                Bucket=self._bucket,
                Key=self._sanitize_key(cache_key),
            )
        except self._client.exceptions.NoSuchKey as exc:  # type: ignore[attr-defined]
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss") from exc
        body = response["Body"]
        return await asyncio.to_thread(body.read)

    def status(self) -> dict[str, object]:
        return {
            "backend": "s3",
            "bucket": self._bucket,
            "endpoint": self._settings.s3_endpoint_url,
        }

    def _sanitize_key(self, cache_key: str) -> str:
        if ".." in cache_key:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cache key")
        return cache_key.lstrip("/")


class CacheProxyState:
    def __init__(self, settings: CacheProxySettings, backend: CacheBackend):
        self.settings = settings
        self.backend = backend


def build_backend(settings: CacheProxySettings) -> CacheBackend:
    if settings.s3_bucket:
        if not settings.s3_endpoint_url:
            raise RuntimeError("S3 configuration incomplete for cache proxy")
        return S3CacheBackend(settings)
    return LocalCacheBackend(settings)


def get_state(app: FastAPI) -> CacheProxyState:
    return app.state.cache_state  # type: ignore[attr-defined]


def require_cache_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    state: CacheProxyState = Depends(get_state),
) -> CacheToken:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing cache token")
    token = authorization.split(" ", 1)[1]
    cache_token = verify_cache_token(state.settings.shared_secret, token)
    if cache_token is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid cache token")
    return cache_token


def create_app() -> FastAPI:
    settings = CacheProxySettings()
    backend = build_backend(settings)
    state = CacheProxyState(settings, backend)
    app = FastAPI()
    app.state.cache_state = state

    @app.put("/cache/{cache_key}", status_code=status.HTTP_201_CREATED)
    async def put_cache(
        cache_key: str,
        request: Request,
        state: CacheProxyState = Depends(get_state),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> Response:
        if cache_token.scope not in {"write", "read_write"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks write scope")
        await state.backend.write(cache_key, request.stream())
        return Response(status_code=status.HTTP_201_CREATED)

    @app.head("/cache/{cache_key}")
    async def head_cache(
        cache_key: str,
        state: CacheProxyState = Depends(get_state),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> Response:
        if cache_token.scope not in {"read", "read_write"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks read scope")
        size = await state.backend.head(cache_key)
        response = Response(status_code=status.HTTP_200_OK)
        response.headers["Content-Length"] = str(size)
        return response

    @app.get("/cache/{cache_key}")
    async def get_cache(
        cache_key: str,
        state: CacheProxyState = Depends(get_state),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> StreamingResponse:
        if cache_token.scope not in {"read", "read_write"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks read scope")
        data = await state.backend.read(cache_key)
        return StreamingResponse(iter([data]), media_type="application/octet-stream")

    @app.get("/status")
    async def status_probe(state: CacheProxyState = Depends(get_state)) -> JSONResponse:
        return JSONResponse(state.backend.status())

    return app
