"""Firecracker lifecycle helpers for the Nimbus host agent."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import structlog

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from ..common.security import verify_cache_token

LOGGER = structlog.get_logger("nimbus.host_agent.firecracker")


@dataclass
class FirecrackerResult:
    """Artifacts emitted after a Firecracker microVM run."""

    job_id: int
    exit_code: int
    log_lines: list[str]
    metrics: Optional[str]


class FirecrackerError(RuntimeError):
    """Raised when Firecracker orchestration fails."""

    def __init__(self, message: str, *, result: Optional[FirecrackerResult] = None) -> None:
        super().__init__(message)
        self.result = result


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

    async def execute_job(self, assignment: JobAssignment, *, timeout_seconds: Optional[int] = None) -> FirecrackerResult:
        """Launch a microVM for the given job and wait for completion."""

        LOGGER.info("Launching microVM", job_id=assignment.job_id)
        with tempfile.TemporaryDirectory(prefix=f"nimbus-job-{assignment.job_id}-") as workdir:
            workdir_path = Path(workdir)
            api_socket = workdir_path / "firecracker.sock"
            log_path = workdir_path / "firecracker.log"
            metrics_path = workdir_path / "firecracker.metrics"

            tap_name = self._allocate_tap_name(assignment.job_id)
            rootfs_copy = self._prepare_rootfs(workdir_path)

            vm_config = self._build_vm_config(rootfs_copy, tap_name)
            metadata = self._build_metadata(assignment)

            tap_created = False
            process: Optional[asyncio.subprocess.Process] = None
            exit_code = -1
            collected: Optional[FirecrackerResult] = None

            try:
                await self._ensure_tap_device(tap_name)
                await self._configure_network(tap_name)
                tap_created = True
                process = await self._spawn_firecracker(api_socket, log_path, metrics_path)
                await self._configure_vm(api_socket, vm_config, metadata)
                await self._start_instance(api_socket)
                try:
                    if timeout_seconds is not None:
                        await asyncio.wait_for(self._wait_for_completion(process), timeout_seconds)
                    else:
                        await self._wait_for_completion(process)
                except asyncio.TimeoutError as exc:
                    if process and process.returncode is None:
                        process.kill()
                        await process.wait()
                    LOGGER.warning("MicroVM execution timed out", job_id=assignment.job_id, timeout_seconds=timeout_seconds)
                    collected = self._collect_artifacts(
                        job_id=assignment.job_id,
                        exit_code=-1,
                        log_path=log_path,
                        metrics_path=metrics_path,
                    )
                    raise FirecrackerError("Job timed out", result=collected) from exc
                exit_code = process.returncode or 0
                collected = self._collect_artifacts(
                    job_id=assignment.job_id,
                    exit_code=exit_code,
                    log_path=log_path,
                    metrics_path=metrics_path,
                )
                return collected
            except Exception as exc:  # noqa: BLE001
                if process and process.returncode is None:
                    process.kill()
                    await process.wait()
                LOGGER.exception("MicroVM execution failed", job_id=assignment.job_id)
                if not collected:
                    collected = self._collect_artifacts(
                        job_id=assignment.job_id,
                        exit_code=exit_code,
                        log_path=log_path,
                        metrics_path=metrics_path,
                    )
                raise FirecrackerError(str(exc), result=collected) from exc
            finally:
                if tap_created:
                    await self._teardown_network(tap_name)
                    await self._teardown_tap_device(tap_name)

    def _allocate_tap_name(self, job_id: int) -> str:
        suffix = job_id % 10000
        return f"{self._settings.tap_device_prefix}{suffix:04d}"

    def _prepare_rootfs(self, workdir: Path) -> Path:
        source = Path(self._settings.rootfs_image_path)
        destination = workdir / source.name
        LOGGER.debug("Preparing rootfs", source=str(source), dest=str(destination))
        if not source.exists():
            raise FirecrackerError(f"Rootfs image not found: {source}")
        try:
            shutil.copy2(source, destination)
        except OSError as exc:  # pragma: no cover - filesystem dependent
            raise FirecrackerError(f"Failed to copy rootfs: {exc}") from exc
        return destination

    def _build_vm_config(self, rootfs_path: Path, tap_name: str) -> dict:
        config = {
            "boot-source": {
                "kernel_image_path": self._settings.kernel_image_path,
                "boot_args": self._config.kernel_args,
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(rootfs_path),
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
            config["network-interfaces"] = [
                {
                    "iface_id": "eth0",
                    "host_dev_name": tap_name,
                    "guest_mac": self._guest_mac_for_tap(tap_name),
                }
            ]

        return config

    def _build_metadata(self, assignment: JobAssignment) -> dict:
        cache_section = None
        if assignment.cache_token:
            cache_section = assignment.cache_token.model_dump()
        elif self._settings.cache_token_secret and self._settings.cache_token_value:
            fallback = verify_cache_token(
                self._settings.cache_token_secret,
                self._settings.cache_token_value,
            )
            if fallback:
                cache_section = fallback.model_dump()

        return {
            "job": {
                "id": assignment.job_id,
                "run_id": assignment.run_id,
                "run_attempt": assignment.run_attempt,
                "repository": assignment.repository.model_dump(),
                "labels": assignment.labels,
            },
            "runner": {
                "registration_token": assignment.runner_registration.token,
                "registration_expires_at": assignment.runner_registration.expires_at.isoformat(),
            },
            "cache": cache_section,
        }

    async def _ensure_tap_device(self, tap_name: str) -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:  # pragma: no cover - platform specific
            raise FirecrackerError("Host agent requires root privileges to create tap devices")
        LOGGER.debug("Creating tap device", tap=tap_name)
        try:
            process = await asyncio.create_subprocess_exec(
                "ip",
                "tuntap",
                "add",
                "mode",
                "tap",
                tap_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:  # pragma: no cover - depends on host
            raise FirecrackerError("ip command not found; install iproute2") from exc
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise FirecrackerError(
                f"Failed to create tap {tap_name}: {stderr.decode().strip() or stdout.decode().strip()}"
            )

    async def _teardown_tap_device(self, tap_name: str) -> None:
        LOGGER.debug("Deleting tap device", tap=tap_name)
        try:
            process = await asyncio.create_subprocess_exec(
                "ip",
                "tuntap",
                "del",
                "mode",
                "tap",
                tap_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return
        await process.communicate()

    async def _configure_network(self, tap_name: str) -> None:
        LOGGER.debug("Configuring network for tap", tap=tap_name)
        bridge = f"{tap_name}-br"
        await self._run_command("ip", "link", "del", bridge, skip_fail=True)
        await self._run_command("ip", "link", "add", bridge, "type", "bridge")
        await self._run_command("ip", "link", "set", bridge, "up")
        await self._run_command("ip", "link", "set", tap_name, "master", bridge)
        await self._run_command("ip", "link", "set", tap_name, "up")

    async def _teardown_network(self, tap_name: str) -> None:
        bridge = f"{tap_name}-br"
        LOGGER.debug("Tearing down network", tap=tap_name, bridge=bridge)
        await self._run_command("ip", "link", "set", tap_name, "nomaster", skip_fail=True)
        await self._run_command("ip", "link", "set", tap_name, "down", skip_fail=True)
        await self._run_command("ip", "link", "del", bridge, skip_fail=True)

    async def _spawn_firecracker(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
    ) -> asyncio.subprocess.Process:
        process = await asyncio.create_subprocess_exec(
            self._settings.firecracker_bin_path,
            "--api-sock",
            str(api_socket),
            "--log-path",
            str(log_path),
            "--level",
            "Info",
            "--metrics-path",
            str(metrics_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(0.1)
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            raise FirecrackerError(
                f"Firecracker exited prematurely: {stderr.decode().strip() or stdout.decode().strip()}"
            )
        return process

    async def _configure_vm(self, api_socket: Path, config: dict, metadata: dict) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(api_socket))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            await self._put(client, "/machine-config", config["machine-config"])
            await self._put(client, "/boot-source", config["boot-source"])

            for drive in config.get("drives", []):
                await self._put(client, f"/drives/{drive['drive_id']}", drive)

            for netif in config.get("network-interfaces", []):
                await self._put(client, f"/network-interfaces/{netif['iface_id']}", netif)

            # Enable MMDS so the runner inside the VM can fetch metadata.
            await self._put(client, "/mmds/config", {"network_interfaces": ["eth0"]})
            await self._put(client, "/mmds", metadata)

    async def _start_instance(self, api_socket: Path) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(api_socket))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            await self._put(client, "/actions", {"action_type": "InstanceStart"})

    async def _wait_for_completion(self, process: asyncio.subprocess.Process) -> None:
        try:
            await asyncio.wait_for(process.wait(), timeout=self._settings.job_timeout_seconds)
        except asyncio.TimeoutError as exc:
            LOGGER.error("Job timed out; terminating microVM")
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=self._settings.vm_shutdown_grace_seconds)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
            raise FirecrackerError("MicroVM timed out") from exc

    def _guest_mac_for_tap(self, tap_name: str) -> str:
        seed = abs(hash(tap_name))
        mac_bytes = [0x06]
        for shift in (0, 8, 16, 24, 32):
            mac_bytes.append((seed >> shift) & 0xFF)
        mac_bytes = mac_bytes[:6]
        return ":".join(f"{b:02x}" for b in mac_bytes)

    async def _put(self, client: httpx.AsyncClient, path: str, payload: dict) -> None:
        response = await client.put(path, json=payload)
        if response.status_code >= 400:
            raise FirecrackerError(
                f"Firecracker API {path} failed: {response.status_code} {response.text.strip()}"
            )

    def _collect_artifacts(
        self,
        *,
        job_id: int,
        exit_code: int,
        log_path: Path,
        metrics_path: Path,
    ) -> FirecrackerResult:
        log_lines: list[str] = []
        if log_path.exists():
            try:
                with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                    log_lines = [line.rstrip("\n") for line in handle]
            except OSError:
                LOGGER.warning("Failed to read Firecracker log", path=str(log_path))

        metrics_data: Optional[str] = None
        if metrics_path.exists():
            try:
                metrics_data = metrics_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                LOGGER.warning("Failed to read Firecracker metrics", path=str(metrics_path))

        return FirecrackerResult(
            job_id=job_id,
            exit_code=exit_code,
            log_lines=log_lines,
            metrics=metrics_data,
        )

    async def _run_command(
        self,
        *args: str,
        skip_fail: bool = False,
    ) -> None:
        LOGGER.debug("Executing command", args=args)
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            if skip_fail:
                return
            raise FirecrackerError(f"Command not found: {args[0]}")

        stdout, stderr = await process.communicate()
        if process.returncode != 0 and not skip_fail:
            raise FirecrackerError(
                f"Command {' '.join(args)} failed: {stderr.decode().strip() or stdout.decode().strip()}"
            )
