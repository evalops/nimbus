"""Firecracker lifecycle helpers for the Smith host agent."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings


class FirecrackerError(RuntimeError):
    """Raised when Firecracker orchestration fails."""


@dataclass
class MicroVMConfig:
    """Configuration options for launching a microVM."""

    vcpu_count: int = 2
    mem_size_mib: int = 4096
    kernel_args: str = "console=ttyS0 reboot=k panic=1 pci=off"
    tap_device: Optional[str] = None


class FirecrackerLauncher:
    """Creates and supervises Firecracker microVMs for job execution."""

    def __init__(self, settings: HostAgentSettings, config: Optional[MicroVMConfig] = None) -> None:
        self._settings = settings
        self._config = config or MicroVMConfig()

    async def execute_job(self, assignment: JobAssignment) -> None:
        """Launch a microVM for the given job and wait for completion.

        The current prototype stubs the VM execution with a timed wait. The structure
        mirrors the real Firecracker flow so we can plug in the actual lifecycle later.
        """

        # Prepare working directory for generated configuration.
        with tempfile.TemporaryDirectory(prefix=f"smith-job-{assignment.job_id}-") as workdir:
            config_path = Path(workdir) / "vm_config.json"
            api_socket = Path(workdir) / "firecracker.sock"

            vm_tap = self._allocate_tap_name(assignment.job_id)
            vm_config = self._build_vm_config(config_path, vm_tap)

            # TODO: Replace simulated execution with Firecracker launch + runner bootstrap.
            await self._simulate_microvm(vm_config, api_socket)

    def _allocate_tap_name(self, job_id: int) -> str:
        suffix = job_id % 10000
        return f"{self._settings.tap_device_prefix}{suffix:04d}"

    def _build_vm_config(self, config_path: Path, tap_name: str) -> dict:
        data = {
            "boot-source": {
                "kernel_image_path": self._settings.kernel_image_path,
                "boot_args": self._config.kernel_args,
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": self._settings.rootfs_image_path,
                    "is_root_device": True,
                    "is_read_only": False,
                }
            ],
            "machine-config": {
                "vcpu_count": self._config.vcpu_count,
                "mem_size_mib": self._config.mem_size_mib,
                "ht_enabled": False,
            },
        }

        if tap_name:
            data["network-interfaces"] = [
                {
                    "iface_id": "eth0",
                    "host_dev_name": tap_name,
                    "guest_mac": self._guest_mac_for_tap(tap_name),
                }
            ]

        config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    def _guest_mac_for_tap(self, tap_name: str) -> str:
        seed = abs(hash(tap_name))
        mac_bytes = [0x06]
        for shift in (0, 8, 16, 24, 32):
            mac_bytes.append((seed >> shift) & 0xFF)
        mac_bytes = mac_bytes[:6]
        return ":".join(f"{b:02x}" for b in mac_bytes)

    async def _simulate_microvm(self, config: dict, api_socket: Path) -> None:
        """Simulate microVM execution for the prototype."""

        del config  # Placeholder to avoid unused-variable warnings.
        del api_socket
        await asyncio.sleep(1)
