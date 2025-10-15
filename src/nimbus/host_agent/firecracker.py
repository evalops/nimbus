"""Firecracker lifecycle helpers for the Nimbus host agent."""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from uuid import uuid4

import httpx
import structlog

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from ..common.security import verify_cache_token
from .reaper import teardown_job_resources

LOGGER = structlog.get_logger("nimbus.host_agent.firecracker")


@dataclass
class FirecrackerResult:
    """Artifacts emitted after a Firecracker microVM run."""

    job_id: int
    exit_code: int
    log_lines: list[str]
    metrics: Optional[str]


@dataclass
class MicroVMNetwork:
    """Network configuration details for a microVM."""

    tap_name: str
    bridge: str
    host_ip: str
    guest_ip: str
    cidr: int = 24


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

    async def execute_job(
        self,
        assignment: JobAssignment,
        *,
        timeout_seconds: Optional[int] = None,
        network: Optional[MicroVMNetwork] = None,
    ) -> FirecrackerResult:
        """Launch a microVM for the given job and wait for completion."""

        LOGGER.info("Launching microVM", job_id=assignment.job_id)
        with tempfile.TemporaryDirectory(prefix=f"nimbus-job-{assignment.job_id}-") as workdir:
            workdir_path = Path(workdir)
            api_socket = workdir_path / "firecracker.sock"
            log_path = workdir_path / "firecracker.log"
            metrics_path = workdir_path / "firecracker.metrics"

            tap_name = network.tap_name if network else self._allocate_tap_name(assignment.job_id)
            network = network or self._derive_network(tap_name)
            rootfs_copy = self._prepare_rootfs(workdir_path)

            vm_config = self._build_vm_config(rootfs_copy, tap_name)
            metadata = self._build_metadata(assignment, network)

            tap_created = False
            process: Optional[asyncio.subprocess.Process] = None
            exit_code = -1
            collected: Optional[FirecrackerResult] = None

            try:
                await self._ensure_tap_device(tap_name)
                await self._configure_network(network)
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
                # Idempotent teardown - safe to call even if setup partially failed
                await teardown_job_resources(
                    assignment.job_id,
                    self._settings.tap_device_prefix,
                    vm_process=process,
                )

    def _allocate_tap_name(self, job_id: int) -> str:
        suffix = job_id % 10000
        return f"{self._settings.tap_device_prefix}{suffix:04d}"

    def _derive_network(self, tap_name: str) -> MicroVMNetwork:
        suffix = int(tap_name[-4:]) if tap_name[-4:].isdigit() else 0
        subnet = 50 + (suffix % 200)
        host_ip = f"172.31.{subnet}.1"
        guest_ip = f"172.31.{subnet}.2"
        bridge = f"{tap_name}-br"
        return MicroVMNetwork(tap_name=tap_name, bridge=bridge, host_ip=host_ip, guest_ip=guest_ip)

    def network_for_job(self, job_id: int) -> MicroVMNetwork:
        tap_name = self._allocate_tap_name(job_id)
        return self._derive_network(tap_name)

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

    def _build_metadata(self, assignment: JobAssignment, network: Optional[MicroVMNetwork]) -> dict:
        cache_section = None
        if assignment.cache_token:
            cache_section = assignment.cache_token.model_dump()
        elif self._settings.cache_token_secret and self._settings.cache_token_value:
            fallback = verify_cache_token(
                self._settings.cache_token_secret.get_secret_value(),
                self._settings.cache_token_value.get_secret_value(),
            )
            if fallback:
                cache_section = fallback.model_dump()

        payload = {
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
        if network:
            payload["network"] = {
                "guest_ip": network.guest_ip,
                "host_ip": network.host_ip,
                "cidr": network.cidr,
            }
            if self._settings.ssh_authorized_key:
                payload["network"]["authorized_key"] = self._settings.ssh_authorized_key
        return payload

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

    async def _configure_network(self, network: MicroVMNetwork) -> None:
        LOGGER.debug("Configuring network for tap", tap=network.tap_name, bridge=network.bridge)
        await self._run_command("ip", "link", "del", network.bridge, skip_fail=True)
        await self._run_command("ip", "link", "add", network.bridge, "type", "bridge")
        await self._run_command("ip", "link", "set", network.bridge, "up")
        await self._run_command("ip", "link", "set", network.tap_name, "master", network.bridge)
        await self._run_command("ip", "link", "set", network.tap_name, "up")
        await self._run_command(
            "ip",
            "addr",
            "add",
            f"{network.host_ip}/{network.cidr}",
            "dev",
            network.bridge,
            skip_fail=True,
        )

    async def _teardown_network(self, network: MicroVMNetwork) -> None:
        LOGGER.debug("Tearing down network", tap=network.tap_name, bridge=network.bridge)
        await self._run_command(
            "ip",
            "addr",
            "del",
            f"{network.host_ip}/{network.cidr}",
            "dev",
            network.bridge,
            skip_fail=True,
        )
        await self._run_command("ip", "link", "set", network.tap_name, "nomaster", skip_fail=True)
        await self._run_command("ip", "link", "set", network.tap_name, "down", skip_fail=True)
        await self._run_command("ip", "link", "del", network.bridge, skip_fail=True)

    async def _spawn_firecracker(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
    ) -> asyncio.subprocess.Process:
        """Spawn Firecracker, using jailer if configured."""
        if self._settings.jailer_bin_path:
            return await self._spawn_firecracker_with_jailer(api_socket, log_path, metrics_path)
        else:
            return await self._spawn_firecracker_direct(api_socket, log_path, metrics_path)

    async def _spawn_firecracker_direct(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
    ) -> asyncio.subprocess.Process:
        """Spawn Firecracker directly without jailer (less secure)."""
        LOGGER.warning("Running Firecracker without jailer - not recommended for production")
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

    async def _spawn_firecracker_with_jailer(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
    ) -> asyncio.subprocess.Process:
        """Spawn Firecracker using the jailer for security isolation."""
        vm_id = uuid4().hex[:16]
        jailer_chroot = self._settings.jailer_chroot_base / vm_id
        jailer_chroot.mkdir(parents=True, exist_ok=True)
        
        # Prepare chroot directory structure
        (jailer_chroot / "root").mkdir(exist_ok=True)
        (jailer_chroot / "root" / "run").mkdir(exist_ok=True)
        
        # Copy Firecracker binary into chroot
        fc_in_chroot = jailer_chroot / "firecracker"
        shutil.copy2(self._settings.firecracker_bin_path, fc_in_chroot)
        fc_in_chroot.chmod(0o755)
        
        # Build jailer command
        cmd = [
            self._settings.jailer_bin_path,
            "--id", vm_id,
            "--exec-file", str(fc_in_chroot),
            "--uid", str(self._settings.jailer_uid),
            "--gid", str(self._settings.jailer_gid),
            "--chroot-base-dir", str(self._settings.jailer_chroot_base),
            "--new-pid-ns",
        ]
        
        # Add seccomp filter if configured
        if self._settings.seccomp_filter_path and self._settings.seccomp_filter_path.exists():
            cmd.extend(["--seccomp-filter", str(self._settings.seccomp_filter_path)])
        elif self._settings.seccomp_filter_path:
            LOGGER.warning("Seccomp filter configured but not found", path=self._settings.seccomp_filter_path)
        
        # Firecracker arguments after --
        cmd.extend([
            "--",
            "--api-sock", "/run/firecracker.sock",
            "--log-path", str(log_path),
            "--level", "Info",
            "--metrics-path", str(metrics_path),
        ])
        
        LOGGER.info(
            "Spawning Firecracker with jailer",
            vm_id=vm_id,
            uid=self._settings.jailer_uid,
            gid=self._settings.jailer_gid,
            seccomp=self._settings.seccomp_filter_path is not None,
        )
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        # Give jailer time to set up
        await asyncio.sleep(0.2)
        
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            # Cleanup chroot on failure
            shutil.rmtree(jailer_chroot, ignore_errors=True)
            raise FirecrackerError(
                f"Jailer/Firecracker exited prematurely: {stderr.decode().strip() or stdout.decode().strip()}"
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
