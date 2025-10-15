"""Async host agent that polls the Smith control plane for jobs."""

from __future__ import annotations

import asyncio
from datetime import datetime
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx

from ..common.schemas import JobAssignment, JobLeaseRequest, JobLeaseResponse, JobStatusUpdate
from ..common.settings import HostAgentSettings
from ..common.security import verify_cache_token
from .firecracker import FirecrackerError, FirecrackerLauncher, FirecrackerResult

LOGGER = logging.getLogger("smith.host_agent")


class HostAgent:
    """Prototype host agent orchestrating Smith microVM jobs."""

    def __init__(self, settings: HostAgentSettings) -> None:
        self._settings = settings
        self._launcher = FirecrackerLauncher(settings)
        timeout = httpx.Timeout(30.0)
        self._http = httpx.AsyncClient(timeout=timeout)
        self._log_http: Optional[httpx.AsyncClient] = None
        if settings.log_sink_url:
            self._log_http = httpx.AsyncClient(timeout=timeout)
        self._running = False

    async def run(self) -> None:
        self._running = True
        while self._running:
            try:
                response = await self._lease_job()
            except httpx.HTTPError as exc:
                LOGGER.error("Lease request failed", exc_info=exc)
                await asyncio.sleep(5)
                continue

            if response.job is None:
                await asyncio.sleep(response.backoff_seconds)
                continue

            assignment = response.job
            await self._process_job(assignment)

    async def stop(self) -> None:
        self._running = False
        await self._http.aclose()
        if self._log_http:
            await self._log_http.aclose()

    async def _lease_job(self) -> JobLeaseResponse:
        request = JobLeaseRequest(
            agent_id=self._settings.agent_id,
            agent_version="0.1.0",
            capabilities=["firecracker"],
        )
        resp = await self._http.post(
            f"{self._settings.control_plane_base_url}/api/jobs/lease",
            headers=self._auth_headers(),
            json=request.model_dump(),
        )
        resp.raise_for_status()
        return JobLeaseResponse.model_validate(resp.json())

    async def _process_job(self, assignment: JobAssignment) -> None:
        LOGGER.info("Starting job", extra={"job_id": assignment.job_id})
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

        try:
            result = await self._launcher.execute_job(assignment)
        except FirecrackerError as exc:
            await self._emit_logs(assignment, exc.result)
            LOGGER.exception("Job failed", extra={"job_id": assignment.job_id})
            await self._submit_status(assignment, "failed", message=str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Job failed", extra={"job_id": assignment.job_id})
            await self._emit_logs(assignment, None)
            await self._submit_status(assignment, "failed", message=str(exc))
            return

        await self._emit_logs(assignment, result)
        LOGGER.info("Job succeeded", extra={"job_id": assignment.job_id})
        await self._submit_status(assignment, "succeeded")

    async def _submit_status(
        self, assignment: JobAssignment, status: str, *, message: Optional[str] = None
    ) -> None:
        payload = JobStatusUpdate(
            agent_id=self._settings.agent_id,
            job_id=assignment.job_id,
            status=status,  # type: ignore[arg-type]
            message=message,
        )
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
            except httpx.HTTPError as exc:  # pragma: no cover - network dependent
                LOGGER.warning(
                    "Failed to emit logs",
                    extra={"job_id": assignment.job_id, "error": str(exc)},
                )
                break


@asynccontextmanager
async def host_agent(settings: HostAgentSettings) -> AsyncIterator[HostAgent]:
    agent = HostAgent(settings)
    try:
        yield agent
    finally:
        await agent.stop()
