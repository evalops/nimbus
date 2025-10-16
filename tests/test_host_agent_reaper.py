from __future__ import annotations

import asyncio

import pytest

from nimbus.host_agent import reaper


class FakeProcess:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def terminate(self) -> None:
        self.terminated = True

    async def wait(self) -> int:
        await asyncio.sleep(0)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self) -> None:
        self.killed = True


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


@pytest.mark.asyncio
async def test_find_stale_taps_parses_output(monkeypatch):
    async def fake_exec(*args, **kwargs):  # noqa: ANN001
        return FakeProcess(stdout=b"nimbus0001: tap\ninvalid\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    taps = await reaper._find_stale_taps("nimbus")
    assert taps == ["nimbus0001"]


@pytest.mark.asyncio
async def test_find_stale_taps_handles_missing_command(monkeypatch):
    async def fake_exec(*args, **kwargs):  # noqa: ANN001
        raise FileNotFoundError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    taps = await reaper._find_stale_taps("nimbus")
    assert taps == []


@pytest.mark.asyncio
async def test_delete_tap_success_and_failure(monkeypatch):
    calls: list[bool] = []

    async def fake_exec(*args, **kwargs):  # noqa: ANN001
        success = len(calls) == 0
        calls.append(success)
        return FakeProcess(returncode=0 if success else 1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    assert await reaper._delete_tap("tap0") is True
    assert await reaper._delete_tap("tap0") is False


@pytest.mark.asyncio
async def test_delete_bridge_brings_down_then_deletes(monkeypatch):
    sequence: list[tuple[str, ...]] = []

    async def fake_exec(*args, **kwargs):  # noqa: ANN001
        sequence.append(tuple(args))
        return FakeProcess(returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    assert await reaper._delete_bridge("br0") is True
    assert sequence[0][:3] == ("ip", "link", "set")
    assert sequence[1][:3] == ("ip", "link", "del")


@pytest.mark.asyncio
async def test_find_stale_firecracker_processes(monkeypatch):
    async def fake_exec(*args, **kwargs):  # noqa: ANN001
        return FakeProcess(stdout=b"123\nabc\n456\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    pids = await reaper._find_stale_firecracker_processes()
    assert pids == [123, 456]


@pytest.mark.asyncio
async def test_kill_process_handles_failure(monkeypatch):
    async def fake_exec(*args, **kwargs):  # noqa: ANN001
        return FakeProcess(returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    assert await reaper._kill_process(999) is False


class DummyProcess(FakeProcess):
    def __init__(self) -> None:
        super().__init__(returncode=0)
        self.returncode = None


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
