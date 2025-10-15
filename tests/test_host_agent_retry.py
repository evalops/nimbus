from __future__ import annotations

import httpx
import pytest

from nimbus.common.settings import HostAgentSettings
from nimbus.host_agent.agent import HostAgent


@pytest.mark.asyncio
async def test_host_agent_lease_retries(monkeypatch, tmp_path):
    kernel = tmp_path / "kernel"
    rootfs = tmp_path / "rootfs.ext4"
    kernel.write_text("kernel")
    rootfs.write_text("rootfs")

    monkeypatch.setenv("NIMBUS_AGENT_ID", "agent-1")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_URL", "http://localhost:8000")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_TOKEN", "token")
    monkeypatch.setenv("NIMBUS_KERNEL_IMAGE", str(kernel))
    monkeypatch.setenv("NIMBUS_ROOTFS_IMAGE", str(rootfs))
    monkeypatch.setenv("NIMBUS_AGENT_LEASE_RETRIES", "3")
    monkeypatch.setenv("NIMBUS_AGENT_LEASE_RETRY_BASE", "0.01")
    monkeypatch.setenv("NIMBUS_AGENT_LEASE_RETRY_MAX", "0.02")

    settings = HostAgentSettings()
    agent = HostAgent(settings)

    request = httpx.Request("POST", f"{settings.control_plane_base_url}/api/jobs/lease")
    attempts: list[int] = []

    async def fake_post(*args, **kwargs):  # noqa: D401
        attempt_number = len(attempts) + 1
        attempts.append(attempt_number)
        if attempt_number < 3:
            response = httpx.Response(status_code=503, request=request)
            raise httpx.HTTPStatusError("server error", request=request, response=response)
        payload = {"job": None, "backoff_seconds": 5}
        return httpx.Response(status_code=200, json=payload, request=request)

    agent._http.post = fake_post  # type: ignore[assignment]

    sleep_durations: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_durations.append(delay)

    monkeypatch.setattr("nimbus.host_agent.agent.asyncio.sleep", fake_sleep)

    response = await agent._lease_job()

    assert response.job is None
    assert attempts == [1, 2, 3]
    assert sleep_durations == [0.01, 0.02]

    await agent.stop()
