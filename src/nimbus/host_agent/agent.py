"""Async host agent that polls the Nimbus control plane for jobs."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Dict, Optional
from urllib.parse import urlparse

import httpx
import structlog
from opentelemetry import trace

from ..common.schemas import JobAssignment, JobLeaseRequest, JobLeaseResponse, JobStatusUpdate
from ..common.settings import HostAgentSettings
from ..common.metrics import GLOBAL_REGISTRY, Counter, Gauge
from ..common.networking import (
    MetadataEndpointDenylist,
    EgressPolicyPack,
    OfflineEgressEnforcer,
    create_guarded_async_client,
)
from ..common.supply_chain import (
    ImagePolicy,
    ensure_provenance,
    generate_spdx_sbom,
)
from .firecracker import FirecrackerError, FirecrackerLauncher, FirecrackerResult, MicroVMNetwork
from .ssh import ActiveSSHSession, apply_port_forward, remove_port_forward
from .state import AgentStateStore, StoredJobNetwork
from ..optional.ssh_dns import SSHSessionConfig
from .reaper import reap_stale_resources

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
        allowed_registries = list(settings.artifact_registry_allow_list)
        parsed = urlparse(str(settings.control_plane_base_url))
        if parsed.hostname:
            allowed_registries.append(parsed.hostname)
        metadata_denylist = MetadataEndpointDenylist(settings.metadata_endpoint_denylist)
        policy_pack = EgressPolicyPack.from_file(settings.egress_policy_pack)
        self._egress_enforcer = OfflineEgressEnforcer(
            offline_mode=settings.offline_mode,
            metadata_denylist=metadata_denylist,
            policy_pack=policy_pack,
            allowed_registries=allowed_registries,
        )
        self._http = create_guarded_async_client(
            enforcer=self._egress_enforcer,
            timeout=30.0,
        )
        self._log_http: Optional[httpx.AsyncClient] = None
        if settings.log_sink_url:
            self._log_http = create_guarded_async_client(
                enforcer=self._egress_enforcer,
                timeout=30.0,
            )
        self._running = False
        self._metrics_server: Optional[asyncio.AbstractServer] = None
        self._active_jobs = 0
        self._active_jobs_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_host_agent_active_jobs", "Jobs currently being processed", supplier=lambda: float(self._active_jobs))
        )
        self._job_networks: Dict[int, MicroVMNetwork] = {}
        self._ssh_sessions: Dict[str, ActiveSSHSession] = {}
        self._enable_ssh = settings.enable_ssh
        self._last_ssh_sync = 0.0
        self._state_store = AgentStateStore(settings.state_database_url)
        self._image_policy = ImagePolicy.from_paths(settings.image_allow_list_path, settings.image_deny_list_path)
        self._cosign_key = settings.cosign_certificate_authority
        self._require_provenance = settings.provenance_required
        self._sbom_output_path = settings.sbom_output_path

    async def run(self) -> None:
        self._running = True
        await self._state_store.open()
        await self._recover_state()
        await self._ensure_metrics_server()

        if self._sbom_output_path:
            try:
                root = Path(self._settings.rootfs_image_path).resolve().parent
                generate_spdx_sbom(root, self._sbom_output_path)
            except Exception as exc:  # noqa: BLE001 - logging for visibility
                LOGGER.warning("SBOM generation failed", error=str(exc))
        
        # Run reaper on startup to clean up stale resources from previous crashes
        try:
            stats = await reap_stale_resources(tap_prefix=self._settings.tap_device_prefix)
            LOGGER.info("Startup reaper completed", stats=stats)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Startup reaper failed", error=str(exc))
        
        while self._running:
            await self._sync_ssh_sessions()
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
            fence_token = response.fence_token
            lease_ttl = response.lease_ttl_seconds
            await self._process_job(assignment, fence_token=fence_token, lease_ttl=lease_ttl)

    async def stop(self) -> None:
        self._running = False
        await self._http.aclose()
        if self._log_http:
            await self._log_http.aclose()
        if self._metrics_server:
            self._metrics_server.close()
            await self._metrics_server.wait_closed()
            self._metrics_server = None
        await self._state_store.close()

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

    async def _recover_state(self) -> None:
        try:
            pending = await self._state_store.list_jobs()
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("Failed to load persisted job state", error=str(exc))
            return

        if not pending:
            return

        LOGGER.info("Recovering orphaned jobs", count=len(pending))
        for job in pending:
            LOGGER.warning(
                "Cleaning up orphaned job",
                job_id=job.job_id,
                tap=job.tap_name,
                bridge=job.bridge,
            )
            network = MicroVMNetwork(
                tap_name=job.tap_name,
                bridge=job.bridge,
                host_ip=job.host_ip,
                guest_ip=job.guest_ip,
                cidr=job.cidr,
            )
            try:
                await self._launcher.cleanup_network(network)
            except FirecrackerError as exc:
                LOGGER.debug(
                    "Network cleanup during recovery failed",
                    job_id=job.job_id,
                    error=str(exc),
                )
            try:
                await self._submit_status_for_job(
                    job.job_id,
                    "failed",
                    message="host agent restarted before completion",
                )
            except httpx.HTTPError as exc:
                LOGGER.debug(
                    "Failed to notify control plane about orphaned job",
                    job_id=job.job_id,
                    error=str(exc),
                )
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.debug(
                    "Unexpected error notifying control plane",
                    job_id=job.job_id,
                    error=str(exc),
                )
            try:
                await self._state_store.remove_job(job.job_id)
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.debug("Failed to remove recovered job state", job_id=job.job_id, error=str(exc))

    async def _process_job(
        self,
        assignment: JobAssignment,
        *,
        fence_token: Optional[int] = None,
        lease_ttl: int = 300,
    ) -> None:
        with TRACER.start_as_current_span(
            "host_agent.process_job",
            attributes={"nimbus.job_id": assignment.job_id, "nimbus.repo": assignment.repository.full_name},
        ):
            await self._state_store.open()
            LOGGER.info("Starting job", job_id=assignment.job_id, fence_token=fence_token)
            JOB_STARTED_COUNTER.inc()
            self._active_jobs += 1
            status_kwargs: dict[str, object] = {}
            if fence_token is not None:
                status_kwargs["fence_token"] = fence_token
            await self._submit_status(assignment, "starting", **status_kwargs)
            network = self._launcher.network_for_job(assignment.job_id)
            self._job_networks[assignment.job_id] = network
            try:
                ensure_provenance(
                    self._settings.rootfs_image_path,
                    self._image_policy,
                    public_key_path=self._cosign_key,
                    require_provenance=self._require_provenance,
                )
            except Exception as exc:  # noqa: BLE001
                LOGGER.error("Runner image provenance verification failed", error=str(exc))
                status_kwargs = {"message": "runner provenance validation failed"}
                if fence_token is not None:
                    status_kwargs["fence_token"] = fence_token
                await self._submit_status(assignment, "failed", **status_kwargs)
                JOB_FAILED_COUNTER.inc()
                return
            try:
                await self._state_store.record_job(
                    StoredJobNetwork(
                        job_id=assignment.job_id,
                        tap_name=network.tap_name,
                        bridge=network.bridge,
                        host_ip=network.host_ip,
                        guest_ip=network.guest_ip,
                        cidr=network.cidr,
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.warning("Failed to persist job state", job_id=assignment.job_id, error=str(exc))

            # Start heartbeat renewal task if fence token provided
            heartbeat_task: Optional[asyncio.Task] = None
            if fence_token is not None:
                heartbeat_task = asyncio.create_task(
                    self._renew_lease_loop(assignment.job_id, fence_token, lease_ttl)
                )

            timeout_seconds = self._settings.job_timeout_seconds
            try:
                result = await self._launcher.execute_job(
                    assignment,
                    timeout_seconds=timeout_seconds,
                    network=network,
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
                status_kwargs = {"message": str(exc)}
                if fence_token is not None:
                    status_kwargs["fence_token"] = fence_token
                await self._submit_status(assignment, "failed", **status_kwargs)
                JOB_FAILED_COUNTER.inc()
                return
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Job failed", job_id=assignment.job_id)
                await self._emit_logs(assignment, None)
                status_kwargs = {"message": str(exc)}
                if fence_token is not None:
                    status_kwargs["fence_token"] = fence_token
                await self._submit_status(assignment, "failed", **status_kwargs)
                JOB_FAILED_COUNTER.inc()
                return
            else:
                await self._emit_logs(assignment, result)
                LOGGER.info("Job succeeded", job_id=assignment.job_id)
                status_kwargs = {}
                if fence_token is not None:
                    status_kwargs["fence_token"] = fence_token
                await self._submit_status(assignment, "succeeded", **status_kwargs)
                JOB_SUCCEEDED_COUNTER.inc()
            finally:
                # Stop heartbeat renewal
                if heartbeat_task:
                    heartbeat_task.cancel()
                    try:
                        await heartbeat_task
                    except asyncio.CancelledError:
                        pass
                self._active_jobs = max(0, self._active_jobs - 1)
                self._job_networks.pop(assignment.job_id, None)
                try:
                    await self._state_store.remove_job(assignment.job_id)
                except Exception as exc:  # pragma: no cover - defensive
                    LOGGER.debug("Failed to clear stored job state", job_id=assignment.job_id, error=str(exc))
                await self._teardown_sessions_for_job(assignment.job_id, reason="job complete")

    async def _submit_status(
        self,
        assignment: JobAssignment,
        status: str,
        *,
        message: Optional[str] = None,
        fence_token: Optional[int] = None,
    ) -> None:
        kwargs: dict[str, object] = {}
        if message is not None:
            kwargs["message"] = message
        if fence_token is not None:
            kwargs["fence_token"] = fence_token
        await self._submit_status_for_job(assignment.job_id, status, **kwargs)

    async def _submit_status_for_job(
        self,
        job_id: int,
        status: str,
        *,
        message: Optional[str] = None,
        fence_token: Optional[int] = None,
    ) -> None:
        payload = JobStatusUpdate(
            agent_id=self._settings.agent_id,
            job_id=job_id,
            status=status,  # type: ignore[arg-type]
            message=message,
            fence_token=fence_token,
        )
        with TRACER.start_as_current_span("host_agent.job_status"):
            resp = await self._http.post(
                f"{self._settings.control_plane_base_url}/api/jobs/status",
                headers=self._auth_headers(),
                json=payload.model_dump(),
            )
        resp.raise_for_status()

    async def _renew_lease_loop(self, job_id: int, fence_token: int, ttl_seconds: int) -> None:
        """Periodically renew the job lease to maintain ownership."""
        import random
        
        # Renew at 40% of TTL with ±10% jitter to avoid thundering herd
        base_period = max(1, int(ttl_seconds * 0.4))
        jitter = int(base_period * 0.1)
        period = base_period + random.randint(-jitter, jitter)
        
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        while True:
            await asyncio.sleep(period)
            try:
                resp = await self._http.post(
                    f"{self._settings.control_plane_base_url}/api/jobs/lease/renew",
                    headers=self._auth_headers(),
                    json={
                        "job_id": job_id,
                        "agent_id": self._settings.agent_id,
                        "fence_token": fence_token,
                    },
                )
                if resp.status_code == 200:
                    consecutive_failures = 0
                    LOGGER.debug("Lease renewed", job_id=job_id, fence_token=fence_token)
                elif resp.status_code in {409, 410}:
                    # Lease lost or expired - stop renewing
                    LOGGER.error(
                        "Lease renewal rejected - lease lost",
                        job_id=job_id,
                        fence_token=fence_token,
                        status=resp.status_code,
                    )
                    break
                else:
                    consecutive_failures += 1
                    LOGGER.warning(
                        "Lease renewal failed",
                        job_id=job_id,
                        fence_token=fence_token,
                        status=resp.status_code,
                        consecutive_failures=consecutive_failures,
                    )
                    if consecutive_failures >= max_consecutive_failures:
                        LOGGER.error("Too many renewal failures, stopping", job_id=job_id)
                        break
            except httpx.HTTPError as exc:
                consecutive_failures += 1
                LOGGER.warning(
                    "Lease renewal error",
                    job_id=job_id,
                    error=str(exc),
                    consecutive_failures=consecutive_failures,
                )
                if consecutive_failures >= max_consecutive_failures:
                    LOGGER.error("Too many renewal failures, stopping", job_id=job_id)
                    break

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._settings.control_plane_token.get_secret_value()}"}

    async def _emit_logs(
        self,
        assignment: JobAssignment,
        result: Optional[FirecrackerResult],
    ) -> None:
        if not self._log_http or not self._settings.log_sink_url:
            return

        entries = []
        timestamp = datetime.now(UTC).isoformat()
        repo_id = assignment.repository.id
        org_id = assignment.repository.owner_id or repo_id
        
        if result and result.log_lines:
            for line in result.log_lines[:1000]:
                entries.append(
                    {
                        "job_id": assignment.job_id,
                        "agent_id": self._settings.agent_id,
                        "org_id": org_id,
                        "repo_id": repo_id,
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
                    "org_id": org_id,
                    "repo_id": repo_id,
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

    async def _sync_ssh_sessions(self) -> None:
        if not self._enable_ssh:
            return
        now = datetime.now(timezone.utc)
        fetch = False
        current = time.monotonic()
        if current - self._last_ssh_sync >= self._settings.ssh_poll_interval_seconds:
            self._last_ssh_sync = current
            fetch = True

        if fetch:
            try:
                response = await self._http.get(
                    f"{self._settings.control_plane_base_url}/api/agents/ssh/sessions",
                    headers=self._auth_headers(),
                )
                response.raise_for_status()
                pending_sessions = response.json()
            except httpx.HTTPError as exc:
                LOGGER.debug("Failed to fetch SSH sessions", error=str(exc))
                pending_sessions = []
            for session in pending_sessions:
                session_id = session.get("session_id")
                if not session_id or session_id in self._ssh_sessions:
                    continue
                job_id = int(session.get("job_id"))
                network = self._job_networks.get(job_id)
                if not network:
                    LOGGER.debug("SSH session requested for inactive job", session_id=session_id, job_id=job_id)
                    continue
                host_port = int(session.get("host_port"))
                authorized_user = session.get("authorized_user", "runner")
                config = SSHSessionConfig(
                    job_id=job_id,
                    host_port=host_port,
                    vm_ip=network.guest_ip,
                    authorized_user=authorized_user,
                )
                try:
                    rules = await apply_port_forward(config)
                except RuntimeError as exc:
                    LOGGER.error("Failed to configure SSH port forwarding", session_id=session_id, error=str(exc))
                    await self._notify_ssh_failure(session_id, str(exc))
                    continue
                try:
                    activate_resp = await self._http.post(
                        f"{self._settings.control_plane_base_url}/api/ssh/sessions/{session_id}/activate",
                        headers=self._auth_headers(),
                        json={"vm_ip": network.guest_ip},
                    )
                    activate_resp.raise_for_status()
                except httpx.HTTPError as exc:
                    LOGGER.error("Failed to activate SSH session", session_id=session_id, error=str(exc))
                    await remove_port_forward(rules)
                    await self._notify_ssh_failure(session_id, f"activation failed: {exc}")
                    continue
                expires_at_raw = session.get("expires_at")
                if isinstance(expires_at_raw, str) and expires_at_raw.endswith("Z"):
                    expires_at_raw = expires_at_raw.replace("Z", "+00:00")
                expires_at = datetime.fromisoformat(expires_at_raw)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                active = ActiveSSHSession(
                    session_id=session_id,
                    job_id=job_id,
                    host_port=host_port,
                    vm_ip=network.guest_ip,
                    authorized_user=authorized_user,
                    expires_at=expires_at,
                    rules=rules,
                )
                self._ssh_sessions[session_id] = active
                LOGGER.info(
                    "SSH session ready",
                    session_id=session_id,
                    job_id=job_id,
                    host_port=host_port,
                    vm_ip=network.guest_ip,
                )

        for session_id, active in list(self._ssh_sessions.items()):
            if active.expires_at <= now or active.job_id not in self._job_networks:
                reason = "expired" if active.expires_at <= now else "job finished"
                await self._close_session(session_id, active, reason=reason)

    async def _notify_ssh_failure(self, session_id: str, reason: str) -> None:
        payload = {"reason": reason}
        try:
            response = await self._http.post(
                f"{self._settings.control_plane_base_url}/api/ssh/sessions/{session_id}/close",
                headers=self._auth_headers(),
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            LOGGER.debug("Failed to notify control plane about SSH failure", session_id=session_id, error=str(exc))

    async def _close_session(self, session_id: str, active: ActiveSSHSession, *, reason: Optional[str]) -> None:
        LOGGER.info("Closing SSH session", session_id=session_id, reason=reason)
        try:
            await remove_port_forward(active.rules)
        except RuntimeError as exc:
            LOGGER.debug("Failed to remove port forwarding", session_id=session_id, error=str(exc))
        try:
            response = await self._http.post(
                f"{self._settings.control_plane_base_url}/api/ssh/sessions/{session_id}/close",
                headers=self._auth_headers(),
                json={"reason": reason},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            LOGGER.debug("Failed to close SSH session via control plane", session_id=session_id, error=str(exc))
        self._ssh_sessions.pop(session_id, None)

    async def _teardown_sessions_for_job(self, job_id: int, *, reason: str) -> None:
        for session_id, active in list(self._ssh_sessions.items()):
            if active.job_id == job_id:
                await self._close_session(session_id, active, reason=reason)

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
