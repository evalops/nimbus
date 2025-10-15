"""FastAPI application providing Smith control plane APIs."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis, from_url as redis_from_url

from ..common.schemas import (
    JobAssignment,
    JobLeaseRequest,
    JobLeaseResponse,
    JobStatusUpdate,
    WebhookWorkflowJobEvent,
)
from ..common.settings import ControlPlaneSettings
from . import db
from .github import GitHubAppClient
from .jobs import enqueue_job, lease_job

LOGGER = logging.getLogger("smith.control_plane")


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


def verify_agent_token(
    request: Request, settings: ControlPlaneSettings = Depends(get_settings)
) -> None:
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = auth_header.split(" ", 1)[1]
    if token != settings.jwt_secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = ControlPlaneSettings()
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
        payload: WebhookWorkflowJobEvent,
        state: AppState = Depends(_get_state),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        if payload.action != "queued":
            LOGGER.debug("Ignoring webhook action", action=payload.action)
            return Response(status_code=status.HTTP_202_ACCEPTED)

        repo = payload.repository
        LOGGER.info(
            "Enqueuing job",
            extra={
                "job_id": payload.workflow_job.id,
                "repo": repo.full_name,
                "labels": payload.workflow_job.labels,
            },
        )

        runner_token = await state.github_client.create_runner_registration_token(repo.full_name)
        assignment = JobAssignment(
            job_id=payload.workflow_job.id,
            run_id=payload.workflow_job.run_id,
            run_attempt=payload.workflow_job.run_attempt,
            repository=repo,
            labels=payload.workflow_job.labels,
            runner_registration=runner_token,
            cache_token=None,
        )
        await enqueue_job(state.redis, assignment)
        await db.record_job_queued(session, assignment)
        await session.commit()
        return Response(status_code=status.HTTP_202_ACCEPTED)

    @app.post("/api/jobs/lease", response_model=JobLeaseResponse)
    async def lease_job_endpoint(
        request_body: JobLeaseRequest,
        _: None = Depends(verify_agent_token),
        redis_client: Redis = Depends(get_redis),
        session: AsyncSession = Depends(get_session),
    ) -> JobLeaseResponse:
        assignment = await lease_job(redis_client)
        if assignment is None:
            return JobLeaseResponse(job=None, backoff_seconds=5)
        LOGGER.info(
            "Leased job",
            extra={"job_id": assignment.job_id, "agent_id": request_body.agent_id},
        )
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
        _: None = Depends(verify_agent_token),
        session: AsyncSession = Depends(get_session),
    ) -> None:
        LOGGER.info(
            "Job status update",
            extra={
                "job_id": status_update.job_id,
                "agent_id": status_update.agent_id,
                "status": status_update.status,
            },
        )
        await db.record_status_update(session, status_update)
        await session.commit()

    return app
