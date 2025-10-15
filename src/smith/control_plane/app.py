"""FastAPI application providing Smith control plane APIs."""

from __future__ import annotations

import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis, from_url as redis_from_url
import structlog

from ..common.metrics import GLOBAL_REGISTRY, Counter, Gauge
from ..common.schemas import (
    AgentTokenMintRequest,
    AgentTokenResponse,
    JobAssignment,
    JobLeaseRequest,
    JobLeaseResponse,
    JobRecord,
    JobStatusUpdate,
    WebhookWorkflowJobEvent,
)
from ..common.settings import ControlPlaneSettings
from ..common.security import decode_agent_token_payload, mint_agent_token
from . import db
from .github import GitHubAppClient
from .jobs import QUEUE_KEY, enqueue_job, lease_job
from ..common.security import mint_cache_token
from ..common.observability import configure_logging, configure_tracing, instrument_fastapi_app
REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_control_plane_requests_total", "Total control plane requests"))
JOB_LEASE_COUNTER = GLOBAL_REGISTRY.register(Counter("smith_control_plane_job_leases_total", "Total leased jobs"))
QUEUE_LENGTH_GAUGE = GLOBAL_REGISTRY.register(Gauge("smith_control_plane_queue_length", "Current queue length"))

LOGGER = structlog.get_logger("smith.control_plane")


class AppState:
    """Container for application-level shared resources."""

    def __init__(
        self,
        settings: ControlPlaneSettings,
        redis: Redis,
        http_client: httpx.AsyncClient,
        github_client: GitHubAppClient,
        session_factory,
    ) -> None:
        self.settings = settings
        self.redis = redis
        self.http_client = http_client
        self.github_client = github_client
        self.session_factory = session_factory


def _get_state(request: Request) -> AppState:
    state: AppState = request.app.state.container  # type: ignore[attr-defined]
    return state


def get_settings(state: AppState = Depends(_get_state)) -> ControlPlaneSettings:
    return state.settings


def get_redis(state: AppState = Depends(_get_state)) -> Redis:
    return state.redis


def get_github_client(state: AppState = Depends(_get_state)) -> GitHubAppClient:
    return state.github_client


async def get_session(state: AppState = Depends(_get_state)) -> AsyncSession:
    async with state.session_factory() as session:  # type: ignore[call-arg]
        yield session


async def verify_agent_token(
    request: Request,
    state: AppState = Depends(_get_state),
    settings: ControlPlaneSettings = Depends(get_settings),
) -> str:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = auth_header.split(" ", 1)[1]
    decoded = decode_agent_token_payload(settings.agent_token_secret, token)
    if decoded is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")
    agent_id, version = decoded
    async with state.session_factory() as session:  # type: ignore[call-arg]
        record = await db.get_agent_token_record(session, agent_id)
    if record:
        expected_version = int(record.get("token_version", 0))
        if version != expected_version:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token revoked")
    elif version != 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token revoked")
    return agent_id


def verify_admin_token(
    request: Request, settings: ControlPlaneSettings = Depends(get_settings)
) -> str:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = auth_header.split(" ", 1)[1]
    decoded = decode_agent_token_payload(settings.jwt_secret, token)
    if decoded is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin token")
    subject, _ = decoded
    return subject


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = ControlPlaneSettings()
    configure_logging("smith.control_plane", settings.log_level)
    configure_tracing(
        service_name="smith.control_plane",
        endpoint=settings.otel_exporter_endpoint,
        headers=settings.otel_exporter_headers,
        sampler_ratio=settings.otel_sampler_ratio,
    )
    instrument_fastapi_app(app)
    redis = redis_from_url(str(settings.redis_url), decode_responses=False)
    http_client = httpx.AsyncClient(timeout=20)
    github_client = GitHubAppClient(settings=settings, http_client=http_client)
    engine = db.create_engine(settings.database_url)
    await db.ensure_schema(engine)
    session_factory = db.session_factory(engine)
    container = AppState(
        settings=settings,
        redis=redis,
        http_client=http_client,
        github_client=github_client,
        session_factory=session_factory,
    )
    app.state.container = container
    try:
        yield
    finally:
        await redis.aclose()
        await http_client.aclose()
        await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.post("/webhooks/github")
    async def github_webhook(
        request: Request,
        state: AppState = Depends(_get_state),
        session: AsyncSession = Depends(get_session),
        settings: ControlPlaneSettings = Depends(get_settings),
    ) -> Response:
        REQUEST_COUNTER.inc()
        raw_body = await request.body()
        signature = request.headers.get("x-hub-signature-256")
        if not _verify_github_signature(settings.github_webhook_secret, raw_body, signature):
            LOGGER.warning("Webhook signature verification failed")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid webhook signature")

        try:
            payload_dict = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:  # pragma: no cover - payload dependent
            LOGGER.error("Invalid webhook payload", error=str(exc))
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload") from exc

        payload = WebhookWorkflowJobEvent.model_validate(payload_dict)
        if payload.action != "queued":
            LOGGER.debug("Ignoring webhook action", action=payload.action)
            return Response(status_code=status.HTTP_202_ACCEPTED)

        repo = payload.repository
        LOGGER.info(
            "Enqueuing job",
            job_id=payload.workflow_job.id,
            repo=repo.full_name,
            labels=payload.workflow_job.labels,
        )

        runner_token = await state.github_client.create_runner_registration_token(repo.full_name)
        cache_token = mint_cache_token(
            secret=settings.cache_shared_secret,
            organization_id=repo.id,
            ttl_seconds=settings.cache_token_ttl_seconds,
        )
        assignment = JobAssignment(
            job_id=payload.workflow_job.id,
            run_id=payload.workflow_job.run_id,
            run_attempt=payload.workflow_job.run_attempt,
            repository=repo,
            labels=payload.workflow_job.labels,
            runner_registration=runner_token,
            cache_token=cache_token,
        )
        await enqueue_job(state.redis, assignment)
        await db.record_job_queued(session, assignment)
        await session.commit()
        queue_length = await state.redis.llen(QUEUE_KEY)
        QUEUE_LENGTH_GAUGE.set(queue_length)
        return Response(status_code=status.HTTP_202_ACCEPTED)

    @app.post("/api/jobs/lease", response_model=JobLeaseResponse)
    async def lease_job_endpoint(
        request_body: JobLeaseRequest,
        token_agent_id: str = Depends(verify_agent_token),
        redis_client: Redis = Depends(get_redis),
        session: AsyncSession = Depends(get_session),
    ) -> JobLeaseResponse:
        REQUEST_COUNTER.inc()
        if token_agent_id != request_body.agent_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent mismatch")
        assignment = await lease_job(redis_client)
        if assignment is None:
            return JobLeaseResponse(job=None, backoff_seconds=5)
        LOGGER.info(
            "Leased job",
            job_id=assignment.job_id,
            agent_id=request_body.agent_id,
        )
        JOB_LEASE_COUNTER.inc()
        queue_length = await redis_client.llen(QUEUE_KEY)
        QUEUE_LENGTH_GAUGE.set(queue_length)
        await db.mark_job_leased(
            session,
            job_id=assignment.job_id,
            agent_id=request_body.agent_id,
        )
        await session.commit()
        return JobLeaseResponse(job=assignment, backoff_seconds=0)

    @app.post("/api/jobs/status", status_code=status.HTTP_202_ACCEPTED)
    async def job_status(
        status_update: JobStatusUpdate,
        token_agent_id: str = Depends(verify_agent_token),
        session: AsyncSession = Depends(get_session),
    ) -> None:
        REQUEST_COUNTER.inc()
        if token_agent_id != status_update.agent_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent mismatch")
        LOGGER.info(
            "Job status update",
            job_id=status_update.job_id,
            agent_id=status_update.agent_id,
            status=status_update.status,
        )
        await db.record_status_update(session, status_update)
        await session.commit()

    @app.get("/api/jobs/recent", response_model=list[JobRecord])
    async def recent_jobs(
        limit: int = 50,
        _: str = Depends(verify_agent_token),
        session: AsyncSession = Depends(get_session),
    ) -> list[JobRecord]:
        REQUEST_COUNTER.inc()
        limit = max(1, min(limit, 200))
        rows = await db.list_recent_jobs(session, limit=limit)
        return [JobRecord.model_validate(row) for row in rows]

    @app.get("/api/status", status_code=status.HTTP_200_OK)
    async def service_status(
        _: str = Depends(verify_agent_token),
        session: AsyncSession = Depends(get_session),
        redis_client: Redis = Depends(get_redis),
    ) -> dict[str, object]:
        REQUEST_COUNTER.inc()
        queue_length = await redis_client.llen(QUEUE_KEY)
        counts = await db.job_status_counts(session)
        return {
            "queue_length": queue_length,
            "jobs_by_status": counts,
        }

    @app.post("/api/agents/token", response_model=AgentTokenResponse)
    async def mint_agent_token_endpoint(
        request_body: AgentTokenMintRequest,
        _: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
        settings: ControlPlaneSettings = Depends(get_settings),
    ) -> AgentTokenResponse:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            version = await db.rotate_agent_token(session, request_body.agent_id, request_body.ttl_seconds)
            await session.commit()

        token = mint_agent_token(
            agent_id=request_body.agent_id,
            secret=settings.agent_token_secret,
            ttl_seconds=request_body.ttl_seconds,
            version=version,
        )
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=request_body.ttl_seconds)
        LOGGER.info(
            "Minted agent token",
            agent_id=request_body.agent_id,
            version=version,
            ttl=request_body.ttl_seconds,
        )
        return AgentTokenResponse(
            agent_id=request_body.agent_id,
            token=token,
            expires_at=expires_at,
            ttl_seconds=request_body.ttl_seconds,
            version=version,
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint() -> PlainTextResponse:
        return PlainTextResponse(GLOBAL_REGISTRY.render())

    return app


def _verify_github_signature(secret: str, body: bytes, signature: str | None) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    provided = signature.split("=", 1)[1]
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, digest)
