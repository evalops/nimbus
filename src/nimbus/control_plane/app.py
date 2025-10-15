"""FastAPI application providing Nimbus control plane APIs."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis, from_url as redis_from_url
import structlog
from opentelemetry import trace

from ..common.metrics import GLOBAL_REGISTRY, Counter, Gauge, Histogram
from ..common.schemas import (
    AgentTokenMintRequest,
    AgentTokenAuditRecord,
    AgentTokenRecord,
    AgentTokenResponse,
    JobAssignment,
    JobLeaseRequest,
    JobLeaseResponse,
    JobLeaseRenewalRequest,
    JobRecord,
    JobStatusUpdate,
    WebhookWorkflowJobEvent,
    SSHSession,
    SSHSessionRequest,
    SSHSessionActivation,
    SSHSessionCloseRequest,
)
from ..common.settings import ControlPlaneSettings
from ..common.security import decode_agent_token_payload, mint_agent_token
from . import db
from .github import GitHubAppClient
from .jobs import QUEUE_KEY, enqueue_job, lease_job, lease_job_with_fence
from ..common.security import mint_cache_token
from ..common.observability import configure_logging, configure_tracing, instrument_fastapi_app
REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_control_plane_requests_total", "Total control plane requests"))
JOB_LEASE_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_control_plane_job_leases_total", "Total leased jobs"))
QUEUE_LENGTH_GAUGE = GLOBAL_REGISTRY.register(Gauge("nimbus_control_plane_queue_length", "Current queue length"))
WEBHOOK_REPLAY_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_control_plane_webhook_replays_blocked", "Webhook replay attacks blocked"))
ORG_RATE_LIMIT_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_control_plane_org_rate_limits_hit", "Organizations hitting rate limits"))
REQUEST_LATENCY_HISTOGRAM = GLOBAL_REGISTRY.register(
    Histogram(
        "nimbus_control_plane_request_latency_seconds",
        buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
        description="Control plane request latency",
    )
)

LOGGER = structlog.get_logger("nimbus.control_plane")
TRACER = trace.get_tracer("nimbus.control_plane")


def _row_to_ssh_session(row: dict) -> SSHSession:
    created_at = row.get("created_at")
    expires_at = row.get("expires_at")
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    return SSHSession(
        session_id=row["session_id"],
        job_id=row["job_id"],
        agent_id=row["agent_id"],
        host_port=row["host_port"],
        authorized_user=row.get("authorized_user", "runner"),
        status=row.get("status", "pending"),
        created_at=created_at,
        expires_at=expires_at,
        vm_ip=row.get("vm_ip"),
        reason=row.get("reason"),
    )


class RateLimiter:
    def __init__(self, limit: int, interval: float) -> None:
        self.limit = limit
        self.interval = interval
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if self.limit <= 0:
            return True
        now = time.time()
        window = now - self.interval
        bucket = self._events[key]
        while bucket and bucket[0] <= window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


class AppState:
    """Container for application-level shared resources."""

    def __init__(
        self,
        settings: ControlPlaneSettings,
        redis: Redis,
        http_client: httpx.AsyncClient,
        github_client: GitHubAppClient,
        session_factory,
        token_rate_limiter: RateLimiter,
        admin_rate_limiter: RateLimiter,
    ) -> None:
        self.settings = settings
        self.redis = redis
        self.http_client = http_client
        self.github_client = github_client
        self.session_factory = session_factory
        self.token_rate_limiter = token_rate_limiter
        self.admin_rate_limiter = admin_rate_limiter


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
    decoded = decode_agent_token_payload(settings.agent_token_secret.get_secret_value(), token)
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
    decoded = decode_agent_token_payload(settings.jwt_secret.get_secret_value(), token)
    if decoded is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin token")
    subject, _ = decoded
    if settings.admin_allowed_subjects and subject not in settings.admin_allowed_subjects:
        LOGGER.warning("Admin token subject not allowed", subject=subject)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin subject not allowed")

    state: AppState = request.app.state.container  # type: ignore[attr-defined]

    if settings.require_https:
        forwarded_proto = request.headers.get("x-forwarded-proto")
        scheme = forwarded_proto.split(",")[0].strip() if forwarded_proto else request.url.scheme
        if scheme.lower() != "https":
            LOGGER.warning("Admin request rejected: insecure protocol", subject=subject, scheme=scheme)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="HTTPS required")

    if settings.admin_allowed_ips:
        forwarded_for = request.headers.get("x-forwarded-for")
        client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else None)
        if client_ip not in settings.admin_allowed_ips:
            LOGGER.warning("Admin request rejected: IP not allowed", subject=subject, client_ip=client_ip)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin source not allowed")

    if settings.admin_rate_limit > 0 and not state.admin_rate_limiter.allow(subject):
        LOGGER.warning("Admin request rate limited", subject=subject, path=request.url.path)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Admin rate limit exceeded")
    return subject


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = ControlPlaneSettings()
    configure_logging("nimbus.control_plane", settings.log_level)
    configure_tracing(
        service_name="nimbus.control_plane",
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
    rate_limiter = RateLimiter(
        limit=settings.agent_token_rate_limit,
        interval=float(settings.agent_token_rate_interval_seconds),
    )
    admin_rate_limiter = RateLimiter(
        limit=settings.admin_rate_limit,
        interval=float(settings.admin_rate_interval_seconds),
    )
    container = AppState(
        settings=settings,
        redis=redis,
        http_client=http_client,
        github_client=github_client,
        session_factory=session_factory,
        token_rate_limiter=rate_limiter,
        admin_rate_limiter=admin_rate_limiter,
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

    @app.middleware("http")
    async def record_request_latency(request: Request, call_next):  # noqa: ANN001 - FastAPI middleware signature
        start = time.perf_counter()
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            duration = time.perf_counter() - start
            REQUEST_LATENCY_HISTOGRAM.observe(duration)
            LOGGER.info(
                "http_request",
                method=request.method,
                path=request.url.path,
                status=getattr(response, "status_code", None),
                duration_ms=round(duration * 1000, 2),
            )

    @app.post("/webhooks/github")
    async def github_webhook(
        request: Request,
        state: AppState = Depends(_get_state),
        session: AsyncSession = Depends(get_session),
        settings: ControlPlaneSettings = Depends(get_settings),
    ) -> Response:
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("control_plane.github_webhook") as span:
            raw_body = await request.body()
            signature = request.headers.get("x-hub-signature-256")
            delivery_id = request.headers.get("x-github-delivery")
            
            # Verify signature
            if not _verify_github_signature(settings.github_webhook_secret.get_secret_value(), raw_body, signature):
                LOGGER.warning("Webhook signature verification failed")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid webhook signature")
            
            # Check for replay attack via delivery ID (nonce)
            if delivery_id:
                # Check if we've seen this delivery ID before
                seen_key = f"webhook:seen:{delivery_id}"
                redis_client = state.redis_client
                is_replay = await redis_client.get(seen_key)
                if is_replay:
                    WEBHOOK_REPLAY_COUNTER.inc()
                    LOGGER.warning("Webhook replay detected", delivery_id=delivery_id)
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Webhook already processed")
                
                # Mark as seen with 10 minute TTL
                await redis_client.set(seen_key, "1", ex=600)

            try:
                payload_dict = json.loads(raw_body.decode("utf-8"))
            except json.JSONDecodeError as exc:  # pragma: no cover - payload dependent
                LOGGER.error("Invalid webhook payload", error=str(exc))
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload") from exc

            payload = WebhookWorkflowJobEvent.model_validate(payload_dict)
            span.set_attribute("nimbus.webhook.action", payload.action)
            if payload.action != "queued":
                LOGGER.debug("Ignoring webhook action", action=payload.action)
                return Response(status_code=status.HTTP_202_ACCEPTED)

            if "nimbus" not in payload.workflow_job.labels:
                LOGGER.debug(
                    "Ignoring job without nimbus label",
                    job_id=payload.workflow_job.id,
                    labels=payload.workflow_job.labels,
                )
                return Response(status_code=status.HTTP_202_ACCEPTED)

            repo = payload.repository
            span.set_attribute("nimbus.repo", repo.full_name)
            
            # Check per-org rate limit
            org_id = repo.id
            rate_key = f"rate:org:{org_id}"
            redis_client = state.redis_client
            current_count = await redis_client.incr(rate_key)
            if current_count == 1:
                # First request in window, set expiry
                await redis_client.expire(rate_key, settings.org_rate_interval_seconds)
            
            if current_count > settings.org_job_rate_limit:
                ORG_RATE_LIMIT_COUNTER.inc()
                LOGGER.warning(
                    "Org rate limit exceeded",
                    org_id=org_id,
                    repo=repo.full_name,
                    count=current_count,
                    limit=settings.org_job_rate_limit,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Organization rate limit exceeded: {settings.org_job_rate_limit} jobs per {settings.org_rate_interval_seconds}s",
                )
            
            LOGGER.info(
                "Enqueuing job",
                job_id=payload.workflow_job.id,
                repo=repo.full_name,
                labels=payload.workflow_job.labels,
            )

            runner_token = await state.github_client.create_runner_registration_token(repo.full_name)
            cache_token = mint_cache_token(
                secret=settings.cache_shared_secret.get_secret_value(),
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
            span.set_attribute("nimbus.queue_length", queue_length)
            span.set_attribute("nimbus.job_id", str(payload.workflow_job.id))
            return Response(status_code=status.HTTP_202_ACCEPTED)

    @app.post("/api/jobs/lease", response_model=JobLeaseResponse)
    async def lease_job_endpoint(
        request_body: JobLeaseRequest,
        token_agent_id: str = Depends(verify_agent_token),
        redis_client: Redis = Depends(get_redis),
        session: AsyncSession = Depends(get_session),
    ) -> JobLeaseResponse:
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("control_plane.lease_job") as span:
            span.set_attribute("nimbus.agent_id", request_body.agent_id)
            if token_agent_id != request_body.agent_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent mismatch")
            
            # Use fenced leasing with DB-backed lease records
            lease_ttl = 300  # 5 minutes
            result = await lease_job_with_fence(
                redis_client, session, request_body.agent_id, lease_ttl
            )
            if result is None:
                return JobLeaseResponse(job=None, backoff_seconds=5)
            
            assignment, fence_token = result
            span.set_attribute("nimbus.job_id", str(assignment.job_id))
            span.set_attribute("nimbus.fence_token", fence_token)
            LOGGER.info(
                "Leased job",
                job_id=assignment.job_id,
                agent_id=request_body.agent_id,
                fence_token=fence_token,
            )
            JOB_LEASE_COUNTER.inc()
            queue_length = await redis_client.llen(QUEUE_KEY)
            QUEUE_LENGTH_GAUGE.set(queue_length)
            span.set_attribute("nimbus.queue_length", queue_length)
            
            # Mint cache token for the job
            cache_token = None
            if state.settings.cache_shared_secret:
                cache_token = mint_cache_token(
                    secret=state.settings.cache_shared_secret.get_secret_value(),
                    organization_id=assignment.repository.id,
                    ttl_seconds=state.settings.cache_token_ttl_seconds,
                )
                assignment.cache_token = cache_token
            
            await session.commit()
            return JobLeaseResponse(
                job=assignment,
                fence_token=fence_token,
                lease_ttl_seconds=lease_ttl,
                backoff_seconds=0,
            )

    @app.post("/api/jobs/lease/renew", status_code=status.HTTP_200_OK)
    async def renew_job_lease_endpoint(
        renewal: JobLeaseRenewalRequest,
        token_agent_id: str = Depends(verify_agent_token),
        session: AsyncSession = Depends(get_session),
    ) -> dict:
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("control_plane.renew_lease") as span:
            span.set_attribute("nimbus.agent_id", renewal.agent_id)
            span.set_attribute("nimbus.job_id", str(renewal.job_id))
            if token_agent_id != renewal.agent_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent mismatch")
            
            lease_ttl = 300  # 5 minutes
            success = await db.renew_job_lease(
                session, renewal.job_id, renewal.agent_id, renewal.fence_token, lease_ttl
            )
            await session.commit()
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Lease renewal failed - invalid fence token or expired lease",
                )
            
            LOGGER.debug(
                "Lease renewed",
                job_id=renewal.job_id,
                agent_id=renewal.agent_id,
                fence_token=renewal.fence_token,
            )
            return {"renewed": True}

    @app.post("/api/jobs/status", status_code=status.HTTP_202_ACCEPTED)
    async def job_status(
        status_update: JobStatusUpdate,
        token_agent_id: str = Depends(verify_agent_token),
        session: AsyncSession = Depends(get_session),
    ) -> None:
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("control_plane.job_status") as span:
            span.set_attribute("nimbus.agent_id", status_update.agent_id)
            span.set_attribute("nimbus.job_id", str(status_update.job_id))
            span.set_attribute("nimbus.job_status", status_update.status)
            if token_agent_id != status_update.agent_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent mismatch")
            
            # Validate fence token if provided
            if status_update.fence_token is not None:
                valid = await db.validate_lease_fence(
                    session, status_update.job_id, status_update.agent_id, status_update.fence_token
                )
                if not valid:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Invalid or expired lease fence",
                    )
            
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
        admin_subject: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
        settings: ControlPlaneSettings = Depends(get_settings),
    ) -> AgentTokenResponse:
        REQUEST_COUNTER.inc()
        with TRACER.start_as_current_span("control_plane.mint_agent_token") as span:
            span.set_attribute("nimbus.agent_id", request_body.agent_id)
            span.set_attribute("nimbus.admin_subject", admin_subject)
            span.set_attribute("nimbus.ttl_seconds", request_body.ttl_seconds)
            if not state.token_rate_limiter.allow(admin_subject):
                LOGGER.warning(
                    "Agent token request rate limited",
                    agent_id=request_body.agent_id,
                    subject=admin_subject,
                )
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Agent token rotation rate limited")
            async with state.session_factory() as session:  # type: ignore[call-arg]
                version = await db.rotate_agent_token(session, request_body.agent_id, request_body.ttl_seconds)
                await db.record_agent_token_audit(
                    session,
                    agent_id=request_body.agent_id,
                    rotated_by=admin_subject,
                    token_version=version,
                    ttl_seconds=request_body.ttl_seconds,
                )
                await session.commit()

            token = mint_agent_token(
                agent_id=request_body.agent_id,
                secret=settings.agent_token_secret.get_secret_value(),
                ttl_seconds=request_body.ttl_seconds,
                version=version,
            )
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=request_body.ttl_seconds)
            LOGGER.info(
                "Minted agent token",
                agent_id=request_body.agent_id,
                version=version,
                ttl=request_body.ttl_seconds,
                rotated_by=admin_subject,
            )
            span.set_attribute("nimbus.token_version", version)
            return AgentTokenResponse(
                agent_id=request_body.agent_id,
                token=token,
                expires_at=expires_at,
                ttl_seconds=request_body.ttl_seconds,
                version=version,
            )

    @app.post("/api/ssh/sessions", response_model=SSHSession)
    async def create_ssh_session_endpoint(
        request_body: SSHSessionRequest,
        admin_subject: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
        settings: ControlPlaneSettings = Depends(get_settings),
    ) -> SSHSession:
        REQUEST_COUNTER.inc()
        ttl_seconds = request_body.ttl_seconds or settings.ssh_session_default_ttl
        ttl_seconds = max(60, min(ttl_seconds, settings.ssh_session_default_ttl))
        async with state.session_factory() as session:  # type: ignore[call-arg]
            job = await db.get_job(session, request_body.job_id)
            if not job:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
            agent_id = job.get("agent_id")
            if not agent_id:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Job is not currently leased to an agent")
            port = await db.allocate_ssh_port(
                session,
                port_start=settings.ssh_port_range_start,
                port_end=settings.ssh_port_range_end,
            )
            if port is None:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No SSH ports available")
            session_id = uuid4().hex
            record = await db.create_ssh_session(
                session,
                session_id=session_id,
                job_id=request_body.job_id,
                agent_id=agent_id,
                host_port=port,
                authorized_user=request_body.authorized_user,
                ttl_seconds=ttl_seconds,
            )
            await session.commit()
        ssh_session = _row_to_ssh_session(record)
        LOGGER.info(
            "SSH session created",
            session_id=ssh_session.session_id,
            job_id=ssh_session.job_id,
            agent_id=ssh_session.agent_id,
            host_port=ssh_session.host_port,
            requested_by=admin_subject,
        )
        return ssh_session

    @app.get("/api/ssh/sessions", response_model=list[SSHSession])
    async def list_ssh_sessions_endpoint(
        _: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
    ) -> list[SSHSession]:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            rows = await db.list_ssh_sessions(session)
        return [_row_to_ssh_session(row) for row in rows]

    @app.get("/api/agents/ssh/sessions", response_model=list[SSHSession])
    async def list_agent_ssh_sessions(
        token_agent_id: str = Depends(verify_agent_token),
        state: AppState = Depends(_get_state),
    ) -> list[SSHSession]:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            rows = await db.list_agent_pending_ssh_sessions(session, token_agent_id)
        return [_row_to_ssh_session(row) for row in rows]

    @app.post("/api/ssh/sessions/{session_id}/activate", response_model=SSHSession)
    async def activate_ssh_session(
        session_id: str,
        payload: SSHSessionActivation,
        token_agent_id: str = Depends(verify_agent_token),
        state: AppState = Depends(_get_state),
    ) -> SSHSession:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            record = await db.get_ssh_session(session, session_id)
            if not record:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
            if record["agent_id"] != token_agent_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Session owned by another agent")
            if record["status"] == "closed":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Session already closed")
            updated = await db.update_ssh_session(
                session,
                session_id,
                status="active",
                vm_ip=payload.vm_ip,
            )
            await session.commit()
        ssh_session = _row_to_ssh_session(updated)
        LOGGER.info(
            "SSH session activated",
            session_id=session_id,
            agent_id=token_agent_id,
            vm_ip=payload.vm_ip,
        )
        return ssh_session

    @app.post("/api/ssh/sessions/{session_id}/close", response_model=SSHSession)
    async def close_ssh_session_agent(
        session_id: str,
        payload: Optional[SSHSessionCloseRequest] = None,
        token_agent_id: str = Depends(verify_agent_token),
        state: AppState = Depends(_get_state),
    ) -> SSHSession:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            record = await db.get_ssh_session(session, session_id)
            if not record:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
            if record["agent_id"] != token_agent_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Session owned by another agent")
            updated = await db.update_ssh_session(
                session,
                session_id,
                status="closed",
                reason=payload.reason if payload else None,
            )
            await session.commit()
        ssh_session = _row_to_ssh_session(updated)
        LOGGER.info("SSH session closed", session_id=session_id, agent_id=token_agent_id)
        return ssh_session

    @app.post("/api/ssh/sessions/{session_id}/terminate", response_model=SSHSession)
    async def terminate_ssh_session_admin(
        session_id: str,
        payload: Optional[SSHSessionCloseRequest] = None,
        _: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
    ) -> SSHSession:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            record = await db.get_ssh_session(session, session_id)
            if not record:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
            updated = await db.update_ssh_session(
                session,
                session_id,
                status="closed",
                reason=(payload.reason if payload else None) or "terminated by admin",
            )
            await session.commit()
        ssh_session = _row_to_ssh_session(updated)
        LOGGER.info("SSH session terminated", session_id=session_id)
        return ssh_session

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint() -> PlainTextResponse:
        return PlainTextResponse(GLOBAL_REGISTRY.render())

    @app.get("/api/agents", response_model=list[AgentTokenRecord])
    async def list_agent_tokens(
        _: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
    ) -> list[AgentTokenRecord]:
        REQUEST_COUNTER.inc()
        async with state.session_factory() as session:  # type: ignore[call-arg]
            records = await db.list_agent_credentials(session)
        return [
            AgentTokenRecord(
                agent_id=row["agent_id"],
                token_version=row["token_version"],
                rotated_at=row["rotated_at"],
                ttl_seconds=row["ttl_seconds"],
            )
            for row in records
        ]

    @app.get("/api/agents/audit", response_model=list[AgentTokenAuditRecord])
    async def list_agent_token_audit_endpoint(
        limit: int = 50,
        _: str = Depends(verify_admin_token),
        state: AppState = Depends(_get_state),
    ) -> list[AgentTokenAuditRecord]:
        REQUEST_COUNTER.inc()
        limit = max(1, min(limit, 500))
        async with state.session_factory() as session:  # type: ignore[call-arg]
            records = await db.list_agent_token_audit(session, limit=limit)
        return [AgentTokenAuditRecord(**row) for row in records]

    return app


def _verify_github_signature(secret: str, body: bytes, signature: str | None) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    provided = signature.split("=", 1)[1]
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided, digest)
