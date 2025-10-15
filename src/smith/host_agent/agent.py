"""Async host agent that polls the Smith control plane for jobs."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx

from ..common.schemas import JobAssignment, JobLeaseRequest, JobLeaseResponse, JobStatusUpdate
from ..common.settings import HostAgentSettings
from .firecracker import FirecrackerLauncher

LOGGER = logging.getLogger("smith.host_agent")


class HostAgent:
    """Prototype host agent orchestrating Smith microVM jobs."""

    def __init__(self, settings: HostAgentSettings) -> None:
        self._settings = settings
        self._launcher = FirecrackerLauncher(settings)
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
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

        try:
            await self._launcher.execute_job(assignment)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Job failed", extra={"job_id": assignment.job_id})
            await self._submit_status(assignment, "failed", message=str(exc))
            return

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


@asynccontextmanager
async def host_agent(settings: HostAgentSettings) -> AsyncIterator[HostAgent]:
    agent = HostAgent(settings)
    try:
        yield agent
    finally:
        await agent.stop()
