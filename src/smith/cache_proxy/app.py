"""Minimal cache proxy service storing artifacts on local disk."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from ..common.schemas import CacheToken
from ..common.settings import CacheProxySettings


def sanitize_key(storage_dir: Path, cache_key: str) -> Path:
    root = storage_dir.resolve()
    candidate = root.joinpath(*cache_key.split("/"))
    resolved = candidate.resolve(strict=False)
    if not str(resolved).startswith(str(root)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cache key")
    return resolved


def get_settings() -> CacheProxySettings:
    return CacheProxySettings()


def require_cache_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    settings: CacheProxySettings = Depends(get_settings),
) -> CacheToken:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing cache token")
    token = authorization.split(" ", 1)[1]
    if token != settings.shared_secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid cache token")

    # Prototype: treat shared secret as read/write org 0 token.
    return CacheToken(token=token, organization_id=0, expires_at=datetime.now(timezone.utc), scope="read_write")


def create_app() -> FastAPI:
    app = FastAPI()

    @app.put("/cache/{cache_key}", status_code=status.HTTP_201_CREATED)
    async def put_cache(
        cache_key: str,
        request: Request,
        settings: CacheProxySettings = Depends(get_settings),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> Response:
        if cache_token.scope not in {"write", "read_write"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks write scope")
        path = sanitize_key(settings.storage_path, cache_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as file_obj:
            async for chunk in request.stream():
                file_obj.write(chunk)
        return Response(status_code=status.HTTP_201_CREATED)

    @app.head("/cache/{cache_key}")
    async def head_cache(
        cache_key: str,
        settings: CacheProxySettings = Depends(get_settings),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> Response:
        if cache_token.scope not in {"read", "read_write"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks read scope")
        path = sanitize_key(settings.storage_path, cache_key)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss")
        response = Response(status_code=status.HTTP_200_OK)
        response.headers["Content-Length"] = str(path.stat().st_size)
        return response

    @app.get("/cache/{cache_key}")
    async def get_cache(
        cache_key: str,
        settings: CacheProxySettings = Depends(get_settings),
        cache_token: CacheToken = Depends(require_cache_token),
    ) -> StreamingResponse:
        if cache_token.scope not in {"read", "read_write"}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cache token lacks read scope")
        path = sanitize_key(settings.storage_path, cache_key)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cache miss")

        async def file_iterator():
            with path.open("rb") as file_obj:
                while True:
                    chunk = file_obj.read(1024 * 1024)
                    if not chunk:
                        break
                    yield chunk

        return StreamingResponse(file_iterator(), media_type="application/octet-stream")

    @app.get("/status")
    async def status_probe(settings: CacheProxySettings = Depends(get_settings)) -> JSONResponse:
        storage = settings.storage_path
        storage.mkdir(parents=True, exist_ok=True)
        return JSONResponse({"storage_path": str(storage), "writable": storage.exists() and os.access(storage, os.W_OK)})

    return app
