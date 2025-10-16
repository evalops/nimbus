from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from nimbus.common.schemas import GitHubRepository, JobAssignment, RunnerRegistrationToken
from nimbus.common.settings import HostAgentSettings
from nimbus.host_agent.agent import HostAgent, JOB_TIMEOUT_COUNTER, JOB_TIMEOUT_LAST_TS
from nimbus.host_agent.firecracker import FirecrackerError, FirecrackerResult, MicroVMNetwork


class TimeoutLauncher:
    async def execute_job(
        self,
        assignment: JobAssignment,
        *,
        timeout_seconds: int | None = None,
        network: MicroVMNetwork | None = None,
    ) -> None:  # noqa: D401
        await asyncio.sleep(0)
        raise FirecrackerError(
            "Job timed out",
            result=FirecrackerResult(
                job_id=assignment.job_id,
                exit_code=-1,
                log_lines=[],
                metrics=None,
            ),
        )

    def network_for_job(self, job_id: int) -> MicroVMNetwork:
        return MicroVMNetwork(
            tap_name=f"tap{job_id:04d}",
            bridge=f"tap{job_id:04d}-br",
            host_ip="172.31.100.1",
            guest_ip="172.31.100.2",
        )


@pytest.mark.asyncio
async def test_host_agent_watchdog_records_timeout(tmp_path, monkeypatch):
    kernel = tmp_path / "kernel"
    rootfs = tmp_path / "rootfs.ext4"
    kernel.write_text("kernel")
    rootfs.write_text("rootfs")

    monkeypatch.setenv("NIMBUS_AGENT_ID", "agent-1")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_URL", "http://localhost:8000")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_TOKEN", "token")
    monkeypatch.setenv("NIMBUS_KERNEL_IMAGE", str(kernel))
    monkeypatch.setenv("NIMBUS_ROOTFS_IMAGE", str(rootfs))
    monkeypatch.setenv("NIMBUS_JOB_TIMEOUT", "1")
    monkeypatch.setenv(
        "NIMBUS_AGENT_STATE_DATABASE_URL",
        f"sqlite+aiosqlite:///{(tmp_path / 'agent_state.db').as_posix()}",
    )

    settings = HostAgentSettings()

    agent = HostAgent(settings)
    agent._launcher = TimeoutLauncher()  # type: ignore[assignment]

    statuses: list[tuple[str, str | None]] = []

    async def fake_submit_status(assignment: JobAssignment, status: str, *, message: str | None = None) -> None:
        statuses.append((status, message))

    async def fake_emit_logs(*args, **kwargs) -> None:  # noqa: D401
        return None

    agent._submit_status = fake_submit_status  # type: ignore[assignment]
    agent._emit_logs = fake_emit_logs  # type: ignore[assignment]

    JOB_TIMEOUT_LAST_TS.set(0.0)
    before = JOB_TIMEOUT_COUNTER._value

    repo = GitHubRepository(id=1, name="demo", full_name="acme/demo", private=False)
    assignment = JobAssignment(
        job_id=101,
        run_id=202,
        run_attempt=1,
        repository=repo,
        labels=["firecracker"],
        runner_registration=RunnerRegistrationToken(
            token="runner",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ),
        cache_token=None,
    )

    await agent._process_job(assignment)

    assert JOB_TIMEOUT_COUNTER._value == before + 1
    assert JOB_TIMEOUT_LAST_TS._value > 0
    assert statuses[-1][0] == "failed"
    assert statuses[-1][1] is not None and "timed out" in statuses[-1][1]

    await agent.stop()
