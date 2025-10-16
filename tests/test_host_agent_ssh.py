from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from nimbus.host_agent.agent import HostAgent
from nimbus.host_agent.firecracker import MicroVMNetwork
from nimbus.common.settings import HostAgentSettings


class DummyHTTPClient:
    def __init__(self, job_id: int) -> None:
        self.job_id = job_id
        self.calls: list[tuple[str, str, dict | None]] = []
        self._pending = [
            {
                "session_id": "sess-1",
                "job_id": job_id,
                "agent_id": "agent-1",
                "host_port": 23001,
                "authorized_user": "runner",
                "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat(),
            }
        ]

    async def get(self, url: str, headers: dict) -> httpx.Response:
        self.calls.append(("GET", url, None))
        request = httpx.Request("GET", url, headers=headers)
        return httpx.Response(200, json=self._pending, request=request)

    async def post(self, url: str, headers: dict, json: dict) -> httpx.Response:
        self.calls.append(("POST", url, json))
        request = httpx.Request("POST", url, headers=headers, json=json)
        return httpx.Response(200, json={"status": "ok"}, request=request)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_host_agent_ssh_session_lifecycle(monkeypatch, tmp_path: Path) -> None:
    kernel = tmp_path / "vmlinux"
    rootfs = tmp_path / "rootfs.ext4"
    kernel.write_text("kernel")
    rootfs.write_text("rootfs")

    monkeypatch.setenv("NIMBUS_AGENT_ID", "agent-1")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_URL", "http://control-plane")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_TOKEN", "token")
    monkeypatch.setenv("NIMBUS_KERNEL_IMAGE", str(kernel))
    monkeypatch.setenv("NIMBUS_ROOTFS_IMAGE", str(rootfs))
    monkeypatch.setenv("NIMBUS_SSH_ENABLE", "1")
    monkeypatch.setenv("NIMBUS_SSH_POLL_INTERVAL", "0")
    monkeypatch.setenv(
        "NIMBUS_AGENT_STATE_DATABASE_URL",
        f"sqlite+aiosqlite:///{(tmp_path / 'agent_state.db').as_posix()}",
    )

    settings = HostAgentSettings()

    agent = HostAgent(settings)
    dummy_http = DummyHTTPClient(job_id=7)
    agent._http = dummy_http  # type: ignore[assignment]
    agent._last_ssh_sync = float("-inf")
    network = MicroVMNetwork(
        tap_name="tap0007",
        bridge="tap0007-br",
        host_ip="172.31.50.1",
        guest_ip="172.31.50.2",
    )
    agent._job_networks[7] = network

    applied_configs = {}

    async def fake_apply(config):
        applied_configs["config"] = config
        return [["iptables", "-A", "PREROUTING"]]

    async def fake_remove(rules):
        applied_configs["removed"] = True

    monkeypatch.setattr("nimbus.host_agent.agent.apply_port_forward", fake_apply)
    monkeypatch.setattr("nimbus.host_agent.agent.remove_port_forward", fake_remove)

    await agent._sync_ssh_sessions()

    assert "config" in applied_configs
    assert applied_configs["config"].job_id == 7
    assert agent._ssh_sessions

    session_id, active = next(iter(agent._ssh_sessions.items()))
    active.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    await agent._sync_ssh_sessions()

    assert not agent._ssh_sessions
    assert applied_configs.get("removed") is True
    close_calls = [call for call in dummy_http.calls if call[0] == "POST" and "close" in call[1]]
    assert close_calls

    await agent.stop()
