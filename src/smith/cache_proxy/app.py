"""Minimal cache proxy service storing artifacts on local disk."""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse

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


def create_app() -> FastAPI:
    app = FastAPI()

    @app.put("/cache/{cache_key}", status_code=status.HTTP_201_CREATED)
    async def put_cache(
        cache_key: str,
        request: Request,
        settings: CacheProxySettings = Depends(get_settings),
    ) -> Response:
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
    ) -> Response:
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
    ) -> StreamingResponse:
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

    return app
