from __future__ import annotations

import asyncio

import pytest

from nimbus.host_agent import reaper


@pytest.mark.asyncio
async def test_reap_stale_resources(monkeypatch):
    async def fake_find_taps(prefix: str):  # noqa: ANN001
        return ["nimbus0001", "nimbus0002"]

    async def fake_delete_bridge(name: str):  # noqa: ANN001
        return True

    async def fake_delete_tap(name: str):  # noqa: ANN001
        return True

    async def fake_find_processes():  # noqa: ANN001
        return [100, 101]

    async def fake_kill(pid: int):  # noqa: ANN001
        return True

    monkeypatch.setattr(reaper, "_find_stale_taps", fake_find_taps)
    monkeypatch.setattr(reaper, "_delete_bridge", fake_delete_bridge)
    monkeypatch.setattr(reaper, "_delete_tap", fake_delete_tap)
    monkeypatch.setattr(reaper, "_find_stale_firecracker_processes", fake_find_processes)
    monkeypatch.setattr(reaper, "_kill_process", fake_kill)

    stats = await reaper.reap_stale_resources(tap_prefix="nimbus")
    assert stats == {"taps_deleted": 2, "bridges_deleted": 2, "processes_killed": 2}


class DummyProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    async def wait(self) -> int:
        await asyncio.sleep(0)
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.killed = True


@pytest.mark.asyncio
async def test_teardown_job_resources(monkeypatch):
    called = {"bridge": None, "tap": None}

    async def fake_delete_bridge(name: str):  # noqa: ANN001
        called["bridge"] = name
        return True

    async def fake_delete_tap(name: str):  # noqa: ANN001
        called["tap"] = name
        return True

    monkeypatch.setattr(reaper, "_delete_bridge", fake_delete_bridge)
    monkeypatch.setattr(reaper, "_delete_tap", fake_delete_tap)

    process = DummyProcess()

    await reaper.teardown_job_resources(42, "nimbus", vm_process=process)

    assert process.terminated is True
    assert called["bridge"] == "nimbus0042-br"
    assert called["tap"] == "nimbus0042"
