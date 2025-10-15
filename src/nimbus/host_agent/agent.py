"""Async host agent that polls the Nimbus control plane for jobs."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx
import structlog
from opentelemetry import trace

from ..common.schemas import JobAssignment, JobLeaseRequest, JobLeaseResponse, JobStatusUpdate
from ..common.settings import HostAgentSettings
from ..common.security import verify_cache_token
from ..common.metrics import GLOBAL_REGISTRY, Counter, Gauge
from .firecracker import FirecrackerError, FirecrackerLauncher, FirecrackerResult

LOGGER = structlog.get_logger("nimbus.host_agent")
TRACER = trace.get_tracer("nimbus.host_agent")

LEASE_REQUEST_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_lease_requests_total", "Lease requests issued to control plane"))
LEASE_ERROR_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_lease_errors_total", "Lease request errors"))
LEASE_EMPTY_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_empty_leases_total", "Lease responses with no work"))
JOB_STARTED_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_jobs_started_total", "Jobs started"))
JOB_SUCCEEDED_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_jobs_succeeded_total", "Jobs succeeded"))
JOB_FAILED_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_jobs_failed_total", "Jobs failed"))
LOG_BATCH_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_log_batches_total", "Log batches emitted"))
LOG_ROWS_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_log_rows_total", "Log rows emitted"))
LOG_ERROR_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_log_errors_total", "Log emission errors"))
JOB_TIMEOUT_COUNTER = GLOBAL_REGISTRY.register(Counter("nimbus_host_agent_job_timeouts_total", "Jobs terminated by watchdog"))
JOB_TIMEOUT_LAST_TS = GLOBAL_REGISTRY.register(Gauge("nimbus_host_agent_last_timeout_timestamp", "Unix timestamp of last job timeout"))


class HostAgent:
    """Prototype host agent orchestrating Nimbus microVM jobs."""

    def __init__(self, settings: HostAgentSettings) -> None:
        self._settings = settings
        self._launcher = FirecrackerLauncher(settings)
        timeout = httpx.Timeout(30.0)
        self._http = httpx.AsyncClient(timeout=timeout)
        self._log_http: Optional[httpx.AsyncClient] = None
        if settings.log_sink_url:
            self._log_http = httpx.AsyncClient(timeout=timeout)
        self._running = False
        self._metrics_server: Optional[asyncio.AbstractServer] = None
        self._active_jobs = 0
        self._active_jobs_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_host_agent_active_jobs", "Jobs currently being processed", supplier=lambda: float(self._active_jobs))
        )

    async def run(self) -> None:
        self._running = True
        await self._ensure_metrics_server()
        while self._running:
            try:
                response = await self._lease_job()
            except httpx.HTTPError as exc:
                LOGGER.exception("Lease request failed", error=str(exc))
                LEASE_ERROR_COUNTER.inc()
                await asyncio.sleep(5)
                continue

            if response.job is None:
                LEASE_EMPTY_COUNTER.inc()
                await asyncio.sleep(response.backoff_seconds)
                continue

            assignment = response.job
            await self._process_job(assignment)

    async def stop(self) -> None:
        self._running = False
        await self._http.aclose()
        if self._log_http:
            await self._log_http.aclose()
        if self._metrics_server:
            self._metrics_server.close()
            await self._metrics_server.wait_closed()
            self._metrics_server = None

    async def _lease_job(self) -> JobLeaseResponse:
        request = JobLeaseRequest(
            agent_id=self._settings.agent_id,
            agent_version="0.1.0",
            capabilities=["firecracker"],
        )
        LEASE_REQUEST_COUNTER.inc()
        attempts = max(1, self._settings.lease_retry_attempts)
        base_delay = max(0.0, self._settings.lease_retry_base_seconds)
        max_delay = max(base_delay, self._settings.lease_retry_max_seconds)
        with TRACER.start_as_current_span("host_agent.lease_job"):
            for attempt in range(1, attempts + 1):
                try:
                    resp = await self._http.post(
                        f"{self._settings.control_plane_base_url}/api/jobs/lease",
                        headers=self._auth_headers(),
                        json=request.model_dump(),
                    )
                    resp.raise_for_status()
                    return JobLeaseResponse.model_validate(resp.json())
                except httpx.HTTPStatusError as exc:
                    status = exc.response.status_code
                    if status < 500 and status not in {429}:
                        raise
                    if attempt >= attempts:
                        raise
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay) if base_delay else 0.0
                    LOGGER.warning(
                        "Lease request failed",
                        attempt=attempt,
                        status=status,
                        retry_in=delay,
                    )
                    if delay:
                        await asyncio.sleep(delay)
                except httpx.HTTPError as exc:
                    if attempt >= attempts:
                        raise
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay) if base_delay else 0.0
                    LOGGER.warning(
                        "Lease request transport error",
                        attempt=attempt,
                        error=str(exc),
                        retry_in=delay,
                    )
                    if delay:
                        await asyncio.sleep(delay)
        raise RuntimeError("Lease retry loop exited unexpectedly")

    async def _process_job(self, assignment: JobAssignment) -> None:
        with TRACER.start_as_current_span(
            "host_agent.process_job",
            attributes={"nimbus.job_id": assignment.job_id, "nimbus.repo": assignment.repository.full_name},
        ):
            LOGGER.info("Starting job", job_id=assignment.job_id)
            JOB_STARTED_COUNTER.inc()
            self._active_jobs += 1
            await self._submit_status(assignment, "starting")

            if (
                not assignment.cache_token
                and self._settings.cache_token_secret
                and self._settings.cache_token_value
            ):
                fallback = verify_cache_token(
                    self._settings.cache_token_secret,
                    self._settings.cache_token_value,
                )
                if fallback:
                    assignment.cache_token = fallback

            timeout_seconds = self._settings.job_timeout_seconds
            try:
                result = await self._launcher.execute_job(
                    assignment,
                    timeout_seconds=timeout_seconds,
                )
            except FirecrackerError as exc:
                await self._emit_logs(assignment, exc.result)
                message = str(exc)
                if "timed out" in message.lower():
                    LOGGER.warning("Job timed out", job_id=assignment.job_id, timeout_seconds=timeout_seconds)
                    JOB_TIMEOUT_COUNTER.inc()
                    JOB_TIMEOUT_LAST_TS.set(time.time())
                else:
                    LOGGER.exception("Job failed", job_id=assignment.job_id)
                await self._submit_status(assignment, "failed", message=str(exc))
                JOB_FAILED_COUNTER.inc()
                return
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Job failed", job_id=assignment.job_id)
                await self._emit_logs(assignment, None)
                await self._submit_status(assignment, "failed", message=str(exc))
                JOB_FAILED_COUNTER.inc()
                return
            else:
                await self._emit_logs(assignment, result)
                LOGGER.info("Job succeeded", job_id=assignment.job_id)
                await self._submit_status(assignment, "succeeded")
                JOB_SUCCEEDED_COUNTER.inc()
            finally:
                self._active_jobs = max(0, self._active_jobs - 1)

    async def _submit_status(
        self, assignment: JobAssignment, status: str, *, message: Optional[str] = None
    ) -> None:
        payload = JobStatusUpdate(
            agent_id=self._settings.agent_id,
            job_id=assignment.job_id,
            status=status,  # type: ignore[arg-type]
            message=message,
        )
        with TRACER.start_as_current_span("host_agent.job_status"):
            resp = await self._http.post(
                f"{self._settings.control_plane_base_url}/api/jobs/status",
                headers=self._auth_headers(),
                json=payload.model_dump(),
            )
        resp.raise_for_status()

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._settings.control_plane_token}"}

    async def _emit_logs(
        self,
        assignment: JobAssignment,
        result: Optional[FirecrackerResult],
    ) -> None:
        if not self._log_http or not self._settings.log_sink_url:
            return

        entries = []
        timestamp = datetime.utcnow().isoformat() + "Z"
        if result and result.log_lines:
            for line in result.log_lines[:1000]:
                entries.append(
                    {
                        "job_id": assignment.job_id,
                        "agent_id": self._settings.agent_id,
                        "level": "info",
                        "message": line,
                        "timestamp": timestamp,
                    }
                )

        if result and result.metrics:
            metrics_msg = result.metrics
            if len(metrics_msg) > 2000:
                metrics_msg = metrics_msg[:2000] + "..."
            entries.append(
                {
                    "job_id": assignment.job_id,
                    "agent_id": self._settings.agent_id,
                    "level": "debug",
                    "message": f"metrics={metrics_msg}",
                    "timestamp": timestamp,
                }
            )

        if not entries:
            return

        url = self._settings.log_sink_url.rstrip("/") + "/logs"
        batch_size = 100
        for idx in range(0, len(entries), batch_size):
            chunk = {"entries": entries[idx : idx + batch_size]}
            try:
                response = await self._log_http.post(url, json=chunk)
                response.raise_for_status()
                LOG_BATCH_COUNTER.inc()
                LOG_ROWS_COUNTER.inc(len(chunk["entries"]))
            except httpx.HTTPError as exc:  # pragma: no cover - network dependent
                LOGGER.warning(
                    "Failed to emit logs",
                    job_id=assignment.job_id,
                    error=str(exc),
                )
                LOG_ERROR_COUNTER.inc()
                break

    async def _ensure_metrics_server(self) -> None:
        if self._metrics_server is not None:
            return

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
            except asyncio.IncompleteReadError:
                writer.close()
                await writer.wait_closed()
                return
            body = GLOBAL_REGISTRY.render().encode("utf-8")
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain; version=0.0.4\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(headers.encode("utf-8") + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            self._metrics_server = await asyncio.start_server(
                handler,
                host=self._settings.metrics_host,
                port=self._settings.metrics_port,
            )
        except OSError as exc:  # pragma: no cover - depends on environment
            LOGGER.warning(
                "Failed to start metrics server",
                host=self._settings.metrics_host,
                port=self._settings.metrics_port,
                error=str(exc),
            )
            self._metrics_server = None
            return
        LOGGER.info(
            "Host agent metrics server listening",
            host=self._settings.metrics_host,
            port=self._settings.metrics_port,
        )


@asynccontextmanager
async def host_agent(settings: HostAgentSettings) -> AsyncIterator[HostAgent]:
    agent = HostAgent(settings)
    try:
        yield agent
    finally:
        await agent.stop()
