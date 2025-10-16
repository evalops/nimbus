"""Lightweight OCI-compatible registry for caching Docker layers."""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Dict, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse, StreamingResponse
import structlog
from opentelemetry import trace
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url

from ..common.metrics import GLOBAL_REGISTRY, Counter, Gauge
from ..common.observability import configure_logging, configure_tracing, instrument_fastapi_app
from ..common.schemas import CacheToken
from ..common.security import verify_cache_token, validate_cache_scope
from ..common.settings import DockerCacheSettings


LOGGER = structlog.get_logger("nimbus.docker_cache")
TRACER = trace.get_tracer("nimbus.docker_cache")


def validate_repository_access(repository: str, token: CacheToken, operation: str) -> None:
    """
    Validate that a cache token can access the given repository.
    
    Repository names should be prefixed with org ID: org-{id}/repo/image
    Enforces org boundaries to prevent cross-org access.
    """
    org_id = token.organization_id
    
    # Validate scope
    if not validate_cache_scope(token, operation, org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token lacks {operation} scope for org {org_id}",
        )
    
    # Enforce org prefix in repository name
    expected_prefix = f"org-{org_id}/"
    if repository.startswith("org-"):
        if not repository.startswith(expected_prefix):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Repository must be under {expected_prefix}",
            )
    else:
        LOGGER.debug(
            "Allowing legacy repository without org prefix",
            repository=repository,
            org_id=org_id,
        )


REQUEST_COUNTER = GLOBAL_REGISTRY.register(
    Counter("nimbus_docker_cache_requests_total", "Total Docker cache registry requests")
)
BLOB_BYTES_WRITTEN_COUNTER = GLOBAL_REGISTRY.register(
    Counter("nimbus_docker_cache_blob_bytes_written_total", "Total bytes of blob data stored")
)
BLOB_BYTES_READ_COUNTER = GLOBAL_REGISTRY.register(
    Counter("nimbus_docker_cache_blob_bytes_read_total", "Total bytes of blob data served")
)
EVICTION_COUNTER = GLOBAL_REGISTRY.register(
    Counter("nimbus_docker_cache_blob_evictions_total", "Number of blob evictions due to storage limits")
)
ACTIVE_UPLOADS_GAUGE = GLOBAL_REGISTRY.register(
    Gauge("nimbus_docker_cache_active_uploads", "Registry uploads currently in progress")
)
TOTAL_BLOB_BYTES_GAUGE = GLOBAL_REGISTRY.register(
    Gauge("nimbus_docker_cache_blob_bytes", "Total bytes consumed by cached blobs")
)


@dataclass
class UploadSession:
    repository: str
    file_path: Path
    hasher: "hashlib._Hash"
    size: int = 0

    async def append(self, chunk: bytes) -> None:
        if not chunk:
            return

        def _write() -> None:
            with self.file_path.open("ab") as handle:
                handle.write(chunk)

        await asyncio.to_thread(_write)
        self.hasher.update(chunk)
        self.size += len(chunk)

    def digest(self) -> str:
        return f"sha256:{self.hasher.hexdigest()}"


class DockerCacheMetrics:
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
                    CREATE TABLE IF NOT EXISTS blobs (
                        digest TEXT PRIMARY KEY,
                        org_id INTEGER,
                        size INTEGER NOT NULL,
                        last_access DOUBLE PRECISION NOT NULL
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS manifests (
                        repository TEXT NOT NULL,
                        reference TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        media_type TEXT,
                        size INTEGER NOT NULL,
                        last_access DOUBLE PRECISION NOT NULL,
                        PRIMARY KEY(repository, reference)
                    )
                    """
                )
            )

    def record_blob(self, digest: str, size: int, org_id: Optional[int] = None) -> None:
        now = time.time()
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO blobs (digest, org_id, size, last_access)
                    VALUES (:digest, :org_id, :size, :last_access)
                    ON CONFLICT(digest) DO UPDATE SET
                        org_id = EXCLUDED.org_id,
                        size = EXCLUDED.size,
                        last_access = EXCLUDED.last_access
                    """
                ),
                {"digest": digest, "org_id": org_id, "size": size, "last_access": now},
            )

    def touch_blob(self, digest: str) -> None:
        now = time.time()
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE blobs SET last_access=:last_access WHERE digest=:digest"),
                {"last_access": now, "digest": digest},
            )

    def delete_blob(self, digest: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(text("DELETE FROM blobs WHERE digest=:digest"), {"digest": digest})

    def total_blob_bytes(self) -> int:
        with self._engine.connect() as conn:
            result = conn.execute(text("SELECT COALESCE(SUM(size), 0) FROM blobs"))
            total = result.scalar_one()
        return int(total or 0)

    def oldest_blobs(self, limit: int = 10) -> list[tuple[str, int]]:
        with self._engine.connect() as conn:
            result = conn.execute(
                text("SELECT digest, size FROM blobs ORDER BY last_access ASC LIMIT :limit"),
                {"limit": limit},
            )
            rows = result.fetchall()
        return [(row[0], int(row[1])) for row in rows]

    def record_manifest(self, repository: str, reference: str, digest: str, media_type: Optional[str], size: int) -> None:
        now = time.time()
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO manifests (repository, reference, digest, media_type, size, last_access)
                    VALUES (:repository, :reference, :digest, :media_type, :size, :last_access)
                    ON CONFLICT(repository, reference) DO UPDATE SET
                        digest = EXCLUDED.digest,
                        media_type = EXCLUDED.media_type,
                        size = EXCLUDED.size,
                        last_access = EXCLUDED.last_access
                    """
                ),
                {
                    "repository": repository,
                    "reference": reference,
                    "digest": digest,
                    "media_type": media_type,
                    "size": size,
                    "last_access": now,
                },
            )

    def resolve_manifest(self, repository: str, reference: str) -> Optional[tuple[str, Optional[str]]]:
        with self._engine.connect() as conn:
            result = conn.execute(
                text("SELECT digest, media_type FROM manifests WHERE repository=:repository AND reference=:reference"),
                {"repository": repository, "reference": reference},
            )
            row = result.fetchone()
        if not row:
            return None
        digest, media_type = row
        self.touch_manifest(repository, reference)
        return digest, media_type

    def touch_manifest(self, repository: str, reference: str) -> None:
        now = time.time()
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE manifests SET last_access=:last_access WHERE repository=:repository AND reference=:reference"),
                {"last_access": now, "repository": repository, "reference": reference},
            )

    def get_blob_org_id(self, digest: str) -> Optional[int]:
        with self._engine.connect() as conn:
            result = conn.execute(text("SELECT org_id FROM blobs WHERE digest=:digest"), {"digest": digest})
            row = result.fetchone()
        return row[0] if row else None


class DockerCacheState:
    def __init__(self, settings: DockerCacheSettings, metrics: DockerCacheMetrics):
        self.settings = settings
        self.metrics = metrics
        self.uploads: Dict[str, UploadSession] = {}
        self._lock = asyncio.Lock()
        self.logger = LOGGER.bind()

    @property
    def storage_path(self) -> Path:
        return self.settings.storage_path

    @property
    def manifests_path(self) -> Path:
        return self.storage_path / "manifests"

    @property
    def blobs_path(self) -> Path:
        return self.storage_path / "blobs"

    async def register_upload(self, repository: str) -> str:
        upload_id = uuid4().hex
        uploads_dir = self.settings.uploads_path
        uploads_dir.mkdir(parents=True, exist_ok=True)
        file_path = uploads_dir / f"{upload_id}.upload"
        if file_path.exists():
            file_path.unlink()
        file_path.touch()
        session = UploadSession(repository=repository, file_path=file_path, hasher=hashlib.sha256())
        async with self._lock:
            self.uploads[upload_id] = session
            ACTIVE_UPLOADS_GAUGE.set(float(len(self.uploads)))
        return upload_id

    async def get_upload(self, upload_id: str) -> UploadSession:
        async with self._lock:
            session = self.uploads.get(upload_id)
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload session not found")
        return session

    async def finalize_upload(self, upload_id: str) -> UploadSession:
        async with self._lock:
            session = self.uploads.pop(upload_id, None)
            ACTIVE_UPLOADS_GAUGE.set(float(len(self.uploads)))
        if not session:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Upload session not found")
        return session

    def blob_path(self, digest: str) -> Path:
        algorithm, value = validate_digest(digest)
        path = self.blobs_path / algorithm / value
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def manifest_path(self, repository: str, reference: str) -> Path:
        base = self.manifests_path / repository
        if is_digest(reference):
            algorithm, value = validate_digest(reference)
            manifest_dir = base / "digests" / algorithm
            manifest_dir.mkdir(parents=True, exist_ok=True)
            return manifest_dir / value
        safe_ref = sanitize_reference(reference)
        manifest_dir = base / "refs"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        return manifest_dir / safe_ref

    def ensure_storage_limit(self) -> None:
        max_bytes = self.settings.max_storage_bytes
        if not max_bytes:
            TOTAL_BLOB_BYTES_GAUGE.set(float(self.metrics.total_blob_bytes()))
            return
        total = self.metrics.total_blob_bytes()
        while total > max_bytes:
            victims = self.metrics.oldest_blobs(limit=1)
            if not victims:
                break
            digest, size = victims[0]
            path = self.blob_path(digest)
            if path.exists():
                path.unlink(missing_ok=True)
            self.metrics.delete_blob(digest)
            total -= size
            EVICTION_COUNTER.inc()
            self.logger.info("blob_evicted", digest=digest, reclaimed_bytes=size)
        TOTAL_BLOB_BYTES_GAUGE.set(float(self.metrics.total_blob_bytes()))


def get_state(request: Request) -> DockerCacheState:
    state = getattr(request.app.state, "cache_state", None)
    if state is None:
        raise RuntimeError("Docker cache state not initialised")
    return state


async def require_cache_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    state: DockerCacheState = Depends(get_state),
) -> CacheToken:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": 'Bearer realm="nimbus-docker-cache"'},
        )
    token_value = authorization.split(" ", 1)[1]
    token = verify_cache_token(state.settings.shared_secret.get_secret_value(), token_value)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cache token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    return token


def validate_digest(digest: str) -> tuple[str, str]:
    if ":" not in digest:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid digest")
    algorithm, value = digest.split(":", 1)
    algorithm = algorithm.lower()
    if algorithm != "sha256" or not value or any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported digest")
    return algorithm, value.lower()


def sanitize_repository(repository: str) -> str:
    parts = [part for part in repository.split("/") if part]
    if not parts:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not specified")
    for part in parts:
        if part in {".", ".."}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid repository name")
        for char in part:
            if char.isalnum() or char in {"_", "-", "."}:
                continue
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid repository name")
    return "/".join(parts)


def sanitize_reference(reference: str) -> str:
    if not reference:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid manifest reference")
    for char in reference:
        if char.isalnum() or char in {"_", "-", "."}:
            continue
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid manifest reference")
    return reference


def is_digest(reference: str) -> bool:
    return ":" in reference


async def iter_file(path: Path) -> AsyncIterator[bytes]:
    loop = asyncio.get_running_loop()
    with path.open("rb") as handle:
        while True:
            data = await loop.run_in_executor(None, handle.read, 1024 * 1024)
            if not data:
                break
            yield data


def create_app() -> FastAPI:
    settings = DockerCacheSettings()
    configure_logging("nimbus.docker_cache", level=settings.log_level)
    configure_tracing(
        "nimbus.docker_cache",
        endpoint=settings.otel_exporter_endpoint,
        headers=settings.otel_exporter_headers,
        sampler_ratio=settings.otel_sampler_ratio,
    )

    metrics = DockerCacheMetrics(settings.metadata_database_url)
    state = DockerCacheState(settings, metrics)

    async def lifespan(app: FastAPI):
        state.storage_path.mkdir(parents=True, exist_ok=True)
        instrument_fastapi_app(app)
        app.state.cache_state = state
        try:
            yield
        finally:
            uploads_dir = settings.uploads_path
            if uploads_dir.exists():
                for leftover in uploads_dir.glob("*.upload"):
                    leftover.unlink(missing_ok=True)

    app = FastAPI(lifespan=lifespan)

    @app.middleware("http")
    async def request_metrics(request: Request, call_next):  # noqa: ANN001 - FastAPI signature
        start = time.perf_counter()
        response: Response | None = None
        try:
            response = await call_next(request)
            return response
        finally:
            duration = time.perf_counter() - start
            REQUEST_COUNTER.inc()
            LOGGER.info(
                "http_request",
                method=request.method,
                path=request.url.path,
                status=getattr(response, "status_code", None),
                duration_ms=round(duration * 1000, 2),
            )

    @app.get("/v2/", response_class=PlainTextResponse)
    async def service_ping(_: CacheToken = Depends(require_cache_token)) -> PlainTextResponse:
        return PlainTextResponse("", status_code=status.HTTP_200_OK)

    @app.post("/v2/{name:path}/blobs/uploads/")
    async def start_blob_upload(
        name: str,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "push")
        upload_id = await state.register_upload(repository)
        location = f"/v2/{repository}/blobs/uploads/{upload_id}"
        headers = {
            "Location": location,
            "Docker-Upload-UUID": upload_id,
            "Range": "0-0",
        }
        return Response(status_code=status.HTTP_202_ACCEPTED, headers=headers)

    async def _append_stream_to_session(session: UploadSession, request: Request) -> None:
        async for chunk in request.stream():
            await session.append(chunk)

    @app.patch("/v2/{name:path}/blobs/uploads/{upload_id}")
    async def upload_blob_chunk(
        name: str,
        upload_id: str,
        request: Request,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "push")
        session = await state.get_upload(upload_id)
        # Validate session repository matches request path
        if session.repository != repository:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Upload session repository mismatch"
            )
        await _append_stream_to_session(session, request)
        headers = {
            "Location": f"/v2/{session.repository}/blobs/uploads/{upload_id}",
            "Docker-Upload-UUID": upload_id,
            "Range": f"0-{max(session.size - 1, 0)}",
        }
        return Response(status_code=status.HTTP_202_ACCEPTED, headers=headers)

    @app.put("/v2/{name:path}/blobs/uploads/{upload_id}")
    async def finalize_blob_upload(
        name: str,
        upload_id: str,
        request: Request,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "push")
        digest_param = request.query_params.get("digest")
        if not digest_param:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="digest query parameter required")
        validate_digest(digest_param)
        session = await state.get_upload(upload_id)
        # Validate session repository matches request path
        if session.repository != repository:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Upload session repository mismatch"
            )
        await _append_stream_to_session(session, request)
        expected_digest = session.digest()
        if expected_digest != digest_param:
            session.file_path.unlink(missing_ok=True)
            await state.finalize_upload(upload_id)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Digest mismatch")

        final_session = await state.finalize_upload(upload_id)
        target_path = state.blob_path(expected_digest)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if target_path.exists():
            target_path.touch()  # update mtime for eviction ordering
            final_session.file_path.unlink(missing_ok=True)
        else:
            os.replace(final_session.file_path, target_path)
        BLOB_BYTES_WRITTEN_COUNTER.inc(final_session.size)
        state.metrics.record_blob(expected_digest, final_session.size, org_id=token.organization_id)
        state.ensure_storage_limit()

        headers = {
            "Location": f"/v2/{repository}/blobs/{expected_digest}",
            "Docker-Content-Digest": expected_digest,
        }
        return Response(status_code=status.HTTP_201_CREATED, headers=headers)

    @app.head("/v2/{name:path}/blobs/{digest}")
    async def stat_blob(
        name: str,
        digest: str,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "pull")
        validate_digest(digest)
        path = state.blob_path(digest)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blob not found")
        # Validate blob ownership
        blob_org_id = state.metrics.get_blob_org_id(digest)
        if blob_org_id is not None and blob_org_id != token.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to blob from different organization"
            )
        size = path.stat().st_size
        state.metrics.touch_blob(digest)
        headers = {"Content-Length": str(size), "Docker-Content-Digest": digest}
        return Response(status_code=status.HTTP_200_OK, headers=headers)

    @app.get("/v2/{name:path}/blobs/{digest}")
    async def fetch_blob(
        name: str,
        digest: str,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> StreamingResponse:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "pull")
        validate_digest(digest)
        path = state.blob_path(digest)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blob not found")
        # Validate blob ownership
        blob_org_id = state.metrics.get_blob_org_id(digest)
        if blob_org_id is not None and blob_org_id != token.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to blob from different organization"
            )
        size = path.stat().st_size
        state.metrics.touch_blob(digest)
        BLOB_BYTES_READ_COUNTER.inc(size)
        headers = {"Docker-Content-Digest": digest}
        return StreamingResponse(iter_file(path), media_type="application/octet-stream", headers=headers)

    @app.delete("/v2/{name:path}/blobs/uploads/{upload_id}")
    async def cancel_upload(
        name: str,
        upload_id: str,
        _: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        sanitize_repository(name)
        session = await state.finalize_upload(upload_id)
        session.file_path.unlink(missing_ok=True)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.put("/v2/{name:path}/manifests/{reference}")
    async def put_manifest(
        name: str,
        reference: str,
        request: Request,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "push")
        body = await request.body()
        if not body:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest body required")
        media_type = request.headers.get("content-type", "application/vnd.docker.distribution.manifest.v2+json")
        digest_value = f"sha256:{hashlib.sha256(body).hexdigest()}"
        manifest_path = state.manifest_path(repository, reference)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(manifest_path.write_bytes, body)
        # Always persist digest copy for retrieval by digest
        digest_path = state.manifest_path(repository, digest_value)
        digest_path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(digest_path.write_bytes, body)
        state.metrics.record_manifest(repository, reference, digest_value, media_type, len(body))
        if not is_digest(reference):
            # Ensure digest lookup metadata is up to date as well
            state.metrics.record_manifest(repository, digest_value, digest_value, media_type, len(body))
        headers = {"Docker-Content-Digest": digest_value}
        return Response(status_code=status.HTTP_201_CREATED, headers=headers)

    async def _read_manifest(state: DockerCacheState, repository: str, reference: str) -> tuple[bytes, str, Optional[str]]:
        path = state.manifest_path(repository, reference)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manifest not found")
        data = await asyncio.to_thread(path.read_bytes)
        digest_value = f"sha256:{hashlib.sha256(data).hexdigest()}"
        metrics_entry = state.metrics.resolve_manifest(repository, reference)
        media_type = metrics_entry[1] if metrics_entry else None
        return data, digest_value, media_type

    @app.get("/v2/{name:path}/manifests/{reference}")
    async def get_manifest(
        name: str,
        reference: str,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "pull")
        data, digest_value, media_type = await _read_manifest(state, repository, reference)
        headers = {"Docker-Content-Digest": digest_value}
        return Response(content=data, media_type=media_type or "application/vnd.docker.distribution.manifest.v2+json", headers=headers)

    @app.head("/v2/{name:path}/manifests/{reference}")
    async def head_manifest(
        name: str,
        reference: str,
        token: CacheToken = Depends(require_cache_token),
        state: DockerCacheState = Depends(get_state),
    ) -> Response:
        repository = sanitize_repository(name)
        validate_repository_access(repository, token, "pull")
        data, digest_value, media_type = await _read_manifest(state, repository, reference)
        headers = {
            "Docker-Content-Digest": digest_value,
            "Content-Length": str(len(data)),
        }
        if media_type:
            headers["Content-Type"] = media_type
        return Response(status_code=status.HTTP_200_OK, headers=headers)

    return app
