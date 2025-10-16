from __future__ import annotations

from pathlib import Path

from nimbus.common.settings import HostAgentSettings
from nimbus.host_agent.firecracker import FirecrackerLauncher


def _seed_host_agent_env(tmp_path: Path, monkeypatch) -> None:
    kernel = tmp_path / "kernel"
    rootfs = tmp_path / "rootfs.ext4"
    kernel.write_text("kernel")
    rootfs.write_text("rootfs")

    monkeypatch.setenv("NIMBUS_AGENT_ID", "agent-1")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_URL", "http://localhost:8000")
    monkeypatch.setenv("NIMBUS_CONTROL_PLANE_TOKEN", "token")
    monkeypatch.setenv("NIMBUS_KERNEL_IMAGE", str(kernel))
    monkeypatch.setenv("NIMBUS_ROOTFS_IMAGE", str(rootfs))
    monkeypatch.setenv(
        "NIMBUS_AGENT_STATE_DATABASE_URL",
        f"sqlite+aiosqlite:///{(tmp_path / 'agent.db').as_posix()}",
    )


def test_rootfs_copy_marked_read_only(tmp_path, monkeypatch):
    _seed_host_agent_env(tmp_path, monkeypatch)
    monkeypatch.setenv("NIMBUS_ENABLE_NETNS", "false")

    settings = HostAgentSettings()
    launcher = FirecrackerLauncher(settings)

    workdir = tmp_path / "workdir"
    workdir.mkdir()

    copy_path, _ = launcher._prepare_rootfs(workdir)

    assert copy_path.exists()
    # Ensure no write bits remain on the staged rootfs
    assert copy_path.stat().st_mode & 0o222 == 0


def test_vm_config_applies_ro_and_rate_limiters(tmp_path, monkeypatch):
    _seed_host_agent_env(tmp_path, monkeypatch)
    monkeypatch.setenv("NIMBUS_ENABLE_NETNS", "false")
    monkeypatch.setenv("NIMBUS_NET_RX_BPS", "1048576")
    monkeypatch.setenv("NIMBUS_NET_TX_BPS", "2097152")
    monkeypatch.setenv("NIMBUS_NET_BURST_BYTES", "524288")

    settings = HostAgentSettings()
    launcher = FirecrackerLauncher(settings)

    config = launcher._build_vm_config("/rootfs/path", "/kernel/path", "tap-test")

    drive = config["drives"][0]
    assert drive["is_root_device"] is True
    assert drive["is_read_only"] is True

    boot_args = config["boot-source"]["boot_args"].split()
    assert boot_args.count("ro") == 1

    (interface,) = config["network-interfaces"]
    assert interface["rx_rate_limiter"]["bandwidth"]["size"] == 1048576
    assert interface["rx_rate_limiter"]["bandwidth"]["one_time_burst"] == 524288
    assert interface["tx_rate_limiter"]["bandwidth"]["size"] == 2097152
    assert interface["tx_rate_limiter"]["bandwidth"]["one_time_burst"] == 524288
