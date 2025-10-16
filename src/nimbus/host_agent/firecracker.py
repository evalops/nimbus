"""Firecracker lifecycle helpers for the Nimbus host agent."""

from __future__ import annotations

import asyncio
import errno
import hashlib
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
from pyroute2 import IPRoute, NetlinkError

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings

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


@dataclass
class FirecrackerContext:
    api_socket_host: Path
    api_socket_guest: str
    log_path_host: Path
    log_path_guest: str
    metrics_path_host: Path
    metrics_path_guest: str
    rootfs_guest_path: str
    kernel_guest_path: str
    rootfs_hash: str
    snapshot_state_host: Optional[Path] = None
    snapshot_state_guest: Optional[str] = None
    snapshot_memory_host: Optional[Path] = None
    snapshot_memory_guest: Optional[str] = None
    jailer_chroot: Optional[Path] = None
    vm_id: Optional[str] = None


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
        self._snapshot_state = Path(settings.snapshot_state_path) if settings.snapshot_state_path else None
        self._snapshot_memory = Path(settings.snapshot_memory_path) if settings.snapshot_memory_path else None
        self._snapshot_enabled = self._snapshot_state is not None and self._snapshot_memory is not None
        self._snapshot_enable_diff = settings.snapshot_enable_diff

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
            rootfs_copy, rootfs_hash = self._prepare_rootfs(workdir_path)
            LOGGER.info(
                "Rootfs prepared",
                job_id=assignment.job_id,
                checksum=rootfs_hash,
                image=Path(self._settings.rootfs_image_path).name,
            )

            metadata = self._build_metadata(assignment, network, rootfs_hash=rootfs_hash)

            tap_created = False
            process: Optional[asyncio.subprocess.Process] = None
            exit_code = -1
            collected: Optional[FirecrackerResult] = None
            spawn_context: Optional[FirecrackerContext] = None

            try:
                await self._ensure_tap_device(tap_name)
                await self._configure_network(network)
                tap_created = True
                process, spawn_context = await self._spawn_firecracker(
                    api_socket,
                    log_path,
                    metrics_path,
                    rootfs_copy,
                    rootfs_hash,
                )

                self._apply_cpu_affinity(process, assignment.job_id)

                if spawn_context.rootfs_hash != rootfs_hash:
                    metadata = self._build_metadata(
                        assignment,
                        network,
                        rootfs_hash=spawn_context.rootfs_hash,
                    )

                if self._snapshot_enabled:
                    await self._restore_snapshot(spawn_context)
                    await self._configure_mmds(spawn_context.api_socket_host, metadata)
                else:
                    vm_config = self._build_vm_config(
                        rootfs_path=spawn_context.rootfs_guest_path,
                        kernel_path=spawn_context.kernel_guest_path,
                        tap_name=tap_name,
                    )
                    await self._configure_vm(spawn_context.api_socket_host, vm_config, metadata)
                await self._start_instance(spawn_context.api_socket_host)
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
                        log_path=spawn_context.log_path_host if spawn_context else log_path,
                        metrics_path=spawn_context.metrics_path_host if spawn_context else metrics_path,
                    )
                    raise FirecrackerError("Job timed out", result=collected) from exc
                exit_code = process.returncode or 0
                collected = self._collect_artifacts(
                    job_id=assignment.job_id,
                    exit_code=exit_code,
                    log_path=spawn_context.log_path_host if spawn_context else log_path,
                    metrics_path=spawn_context.metrics_path_host if spawn_context else metrics_path,
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
                        log_path=spawn_context.log_path_host if spawn_context else log_path,
                        metrics_path=spawn_context.metrics_path_host if spawn_context else metrics_path,
                    )
                raise FirecrackerError(str(exc), result=collected) from exc
            finally:
                if tap_created:
                    await self.cleanup_network(network)
                if spawn_context and spawn_context.jailer_chroot:
                    shutil.rmtree(spawn_context.jailer_chroot, ignore_errors=True)

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

    def _prepare_rootfs(self, workdir: Path) -> tuple[Path, str]:
        source = Path(self._settings.rootfs_image_path)
        destination = workdir / source.name
        LOGGER.debug("Preparing rootfs", source=str(source), dest=str(destination))
        if not source.exists():
            raise FirecrackerError(f"Rootfs image not found: {source}")
        try:
            shutil.copy2(source, destination)
        except OSError as exc:  # pragma: no cover - filesystem dependent
            raise FirecrackerError(f"Failed to copy rootfs: {exc}") from exc
        checksum = self._compute_checksum(destination)
        return destination, checksum

    def _build_vm_config(self, rootfs_path: str, kernel_path: str, tap_name: str) -> dict:
        config = {
            "boot-source": {
                "kernel_image_path": kernel_path,
                "boot_args": self._config.kernel_args,
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": rootfs_path,
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

    def _build_metadata(
        self,
        assignment: JobAssignment,
        network: Optional[MicroVMNetwork],
        *,
        rootfs_hash: Optional[str] = None,
    ) -> dict:
        cache_section = None
        if assignment.cache_token:
            cache_section = assignment.cache_token.model_dump()

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

        if rootfs_hash:
            payload["rootfs"] = {
                "checksum_sha256": rootfs_hash,
                "image": Path(self._settings.rootfs_image_path).name,
            }
        return payload

    async def _ensure_tap_device(self, tap_name: str) -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:  # pragma: no cover - platform specific
            raise FirecrackerError("Host agent requires root privileges to create tap devices")
        LOGGER.debug("Creating tap device", tap=tap_name)
        try:
            await asyncio.to_thread(self._create_tap_device, tap_name)
        except PermissionError as exc:  # pragma: no cover - depends on host capabilities
            raise FirecrackerError("Insufficient privileges to create tap device") from exc
        except NetlinkError as exc:
            if exc.code == errno.EEXIST:
                raise FirecrackerError(f"Tap device {tap_name} already exists") from exc
            raise FirecrackerError(f"Failed to create tap device {tap_name}: {exc}") from exc

    async def _teardown_tap_device(self, tap_name: str) -> None:
        LOGGER.debug("Deleting tap device", tap=tap_name)
        try:
            await asyncio.to_thread(self._delete_link, tap_name, True)
        except NetlinkError as exc:
            LOGGER.debug("Failed to remove tap device", tap=tap_name, error=str(exc))

    async def _configure_network(self, network: MicroVMNetwork) -> None:
        LOGGER.debug("Configuring network for tap", tap=network.tap_name, bridge=network.bridge)
        try:
            await asyncio.to_thread(self._delete_link, network.bridge, True)
            await asyncio.to_thread(self._add_bridge, network.bridge)
            await asyncio.to_thread(self._set_link_state, network.bridge, "up", False)
            await asyncio.to_thread(self._set_master, network.tap_name, network.bridge)
            await asyncio.to_thread(self._set_link_state, network.tap_name, "up", False)
            await asyncio.to_thread(self._assign_address, network.bridge, network.host_ip, network.cidr)
        except NetlinkError as exc:
            raise FirecrackerError(f"Failed to configure network {network.tap_name}: {exc}") from exc

    async def _teardown_network(self, network: MicroVMNetwork) -> None:
        LOGGER.debug("Tearing down network", tap=network.tap_name, bridge=network.bridge)
        try:
            await asyncio.to_thread(self._remove_address, network.bridge, network.host_ip, network.cidr)
            await asyncio.to_thread(self._clear_master, network.tap_name)
            await asyncio.to_thread(self._set_link_state, network.tap_name, "down", True)
            await asyncio.to_thread(self._delete_link, network.bridge, True)
        except NetlinkError as exc:
            LOGGER.debug("Failed to tear down network cleanly", tap=network.tap_name, error=str(exc))

    async def cleanup_network(self, network: MicroVMNetwork) -> None:
        await self._teardown_network(network)
        await self._teardown_tap_device(network.tap_name)

    async def _spawn_firecracker(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
        rootfs_path: Path,
        rootfs_hash: str,
    ) -> tuple[asyncio.subprocess.Process, FirecrackerContext]:
        if self._settings.jailer_bin_path:
            return await self._spawn_firecracker_with_jailer(
                api_socket, log_path, metrics_path, rootfs_path, rootfs_hash
            )
        return await self._spawn_firecracker_direct(
            api_socket, log_path, metrics_path, rootfs_path, rootfs_hash
        )

    async def _spawn_firecracker_direct(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
        rootfs_path: Path,
        rootfs_hash: str,
    ) -> tuple[asyncio.subprocess.Process, FirecrackerContext]:
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
        snapshot_state_host = self._snapshot_state if self._snapshot_enabled else None
        snapshot_memory_host = self._snapshot_memory if self._snapshot_enabled else None
        snapshot_state_guest = str(snapshot_state_host) if snapshot_state_host else None
        snapshot_memory_guest = str(snapshot_memory_host) if snapshot_memory_host else None

        context = FirecrackerContext(
            api_socket_host=api_socket,
            api_socket_guest=str(api_socket),
            log_path_host=log_path,
            log_path_guest=str(log_path),
            metrics_path_host=metrics_path,
            metrics_path_guest=str(metrics_path),
            rootfs_guest_path=str(rootfs_path),
            kernel_guest_path=self._settings.kernel_image_path,
            rootfs_hash=rootfs_hash,
            snapshot_state_host=snapshot_state_host,
            snapshot_state_guest=snapshot_state_guest,
            snapshot_memory_host=snapshot_memory_host,
            snapshot_memory_guest=snapshot_memory_guest,
        )
        return process, context

    async def _spawn_firecracker_with_jailer(
        self,
        api_socket: Path,
        log_path: Path,
        metrics_path: Path,
        rootfs_path: Path,
        rootfs_hash: str,
    ) -> tuple[asyncio.subprocess.Process, FirecrackerContext]:
        if platform.system().lower() != "linux":
            raise FirecrackerError("Jailer is only supported on Linux systems")

        if not self._settings.jailer_chroot_base.exists():
            self._settings.jailer_chroot_base.mkdir(parents=True, exist_ok=True)

        vm_id = uuid4().hex[:16]
        jailer_chroot = self._settings.jailer_chroot_base / vm_id
        (jailer_chroot / "root").mkdir(parents=True, exist_ok=True)
        (jailer_chroot / "root" / "run").mkdir(exist_ok=True)

        # Prepare runtime resources inside chroot
        kernel_src = Path(self._settings.kernel_image_path)
        kernel_dest_dir = jailer_chroot / "root" / "kernel"
        kernel_dest_dir.mkdir(exist_ok=True)
        kernel_dest = kernel_dest_dir / kernel_src.name
        shutil.copy2(kernel_src, kernel_dest)

        rootfs_dest_dir = jailer_chroot / "root" / "rootfs"
        rootfs_dest_dir.mkdir(exist_ok=True)
        rootfs_dest = rootfs_dest_dir / rootfs_path.name
        shutil.copy2(rootfs_path, rootfs_dest)

        snapshot_state_host = None
        snapshot_state_guest = None
        snapshot_memory_host = None
        snapshot_memory_guest = None
        if self._snapshot_enabled:
            if not self._snapshot_state or not self._snapshot_memory:
                raise FirecrackerError("Snapshot paths not configured correctly")
            if not self._snapshot_state.exists() or not self._snapshot_memory.exists():
                raise FirecrackerError("Snapshot files not found for snapshot boot")
            snapshot_dir = jailer_chroot / "root" / "snapshots"
            snapshot_dir.mkdir(exist_ok=True)
            state_dest = snapshot_dir / self._snapshot_state.name
            mem_dest = snapshot_dir / self._snapshot_memory.name
            shutil.copy2(self._snapshot_state, state_dest)
            shutil.copy2(self._snapshot_memory, mem_dest)
            snapshot_state_host = state_dest
            snapshot_state_guest = f"/snapshots/{state_dest.name}"
            snapshot_memory_host = mem_dest
            snapshot_memory_guest = f"/snapshots/{mem_dest.name}"

        fc_in_chroot = jailer_chroot / "firecracker"
        shutil.copy2(self._settings.firecracker_bin_path, fc_in_chroot)
        fc_in_chroot.chmod(0o755)

        api_socket_host = jailer_chroot / "root" / "run" / "firecracker.sock"
        log_path_host = jailer_chroot / "root" / "run" / "firecracker.log"
        metrics_path_host = jailer_chroot / "root" / "run" / "firecracker.metrics"

        cmd = [
            self._settings.jailer_bin_path,
            "--id",
            vm_id,
            "--exec-file",
            str(fc_in_chroot),
            "--uid",
            str(self._settings.jailer_uid),
            "--gid",
            str(self._settings.jailer_gid),
            "--chroot-base-dir",
            str(self._settings.jailer_chroot_base),
            "--new-pid-ns",
        ]

        if self._settings.seccomp_filter_path and self._settings.seccomp_filter_path.exists():
            cmd.extend(["--seccomp-filter", str(self._settings.seccomp_filter_path)])
        elif self._settings.seccomp_filter_path:
            LOGGER.warning(
                "Seccomp filter configured but not found",
                path=str(self._settings.seccomp_filter_path),
            )

        cmd.extend(
            [
                "--",
                "--api-sock",
                "/run/firecracker.sock",
                "--log-path",
                "/run/firecracker.log",
                "--level",
                "Info",
                "--metrics-path",
                "/run/firecracker.metrics",
            ]
        )

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

        await asyncio.sleep(0.2)

        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            shutil.rmtree(jailer_chroot, ignore_errors=True)
            raise FirecrackerError(
                f"Jailer/Firecracker exited prematurely: {stderr.decode().strip() or stdout.decode().strip()}"
            )

        context = FirecrackerContext(
            api_socket_host=api_socket_host,
            api_socket_guest="/run/firecracker.sock",
            log_path_host=log_path_host,
            log_path_guest="/run/firecracker.log",
            metrics_path_host=metrics_path_host,
            metrics_path_guest="/run/firecracker.metrics",
            rootfs_guest_path=f"/rootfs/{rootfs_dest.name}",
            kernel_guest_path=f"/kernel/{kernel_dest.name}",
            rootfs_hash=rootfs_hash,
            snapshot_state_host=snapshot_state_host,
            snapshot_state_guest=snapshot_state_guest,
            snapshot_memory_host=snapshot_memory_host,
            snapshot_memory_guest=snapshot_memory_guest,
            jailer_chroot=jailer_chroot,
            vm_id=vm_id,
        )

        return process, context

    def _select_affinity_set(self, job_id: int) -> set[int]:
        mask = getattr(self._settings, "cpu_affinity", [])
        if not mask:
            return set()
        vcpus = max(1, self._config.vcpu_count)
        count = len(mask)
        selected: set[int] = set()
        start = job_id % count
        for offset in range(min(vcpus, count)):
            selected.add(mask[(start + offset) % count])
        return selected

    def _apply_cpu_affinity(self, process: asyncio.subprocess.Process, job_id: int) -> None:
        if not hasattr(os, "sched_setaffinity"):
            return
        pid = process.pid
        if pid is None:
            return
        cpus = self._select_affinity_set(job_id)
        if not cpus:
            return
        try:
            os.sched_setaffinity(pid, cpus)
            LOGGER.info("Applied CPU affinity", pid=pid, cpus=sorted(cpus))
        except OSError as exc:  # pragma: no cover - platform dependent
            LOGGER.warning("Failed to apply CPU affinity", error=str(exc))

    async def _configure_vm(self, api_socket: Path, config: dict, metadata: dict) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(api_socket))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            await self._put(client, "/machine-config", config["machine-config"])
            await self._put(client, "/boot-source", config["boot-source"])

            for drive in config.get("drives", []):
                await self._put(client, f"/drives/{drive['drive_id']}", drive)

            for netif in config.get("network-interfaces", []):
                await self._put(client, f"/network-interfaces/{netif['iface_id']}", netif)

        await self._configure_mmds(api_socket, metadata)

    async def _configure_mmds(self, api_socket: Path, metadata: dict) -> None:
        transport = httpx.AsyncHTTPTransport(uds=str(api_socket))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            await self._put(client, "/mmds/config", {"network_interfaces": ["eth0"]})
            await self._put(client, "/mmds", metadata)

    async def _restore_snapshot(self, context: FirecrackerContext) -> None:
        if not context.snapshot_state_guest or not context.snapshot_memory_guest:
            raise FirecrackerError("Snapshot paths missing for snapshot boot")
        transport = httpx.AsyncHTTPTransport(uds=str(context.api_socket_host))
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            await self._put(
                client,
                "/snapshot/load",
                {
                    "snapshot_path": context.snapshot_state_guest,
                    "memory_file_path": context.snapshot_memory_guest,
                    "enable_diff_snapshots": self._snapshot_enable_diff,
                },
            )

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

    def _compute_checksum(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

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

    def _create_tap_device(self, tap_name: str) -> None:
        with IPRoute() as ipr:
            ipr.link("add", ifname=tap_name, kind="tuntap", mode="tap")

    def _delete_link(self, ifname: str, ignore_missing: bool) -> None:
        with IPRoute() as ipr:
            indexes = ipr.link_lookup(ifname=ifname)
            if not indexes:
                if ignore_missing:
                    return
                raise NetlinkError(errno.ENODEV, os.strerror(errno.ENODEV))
            ipr.link("del", index=indexes[0])

    def _add_bridge(self, bridge: str) -> None:
        with IPRoute() as ipr:
            try:
                ipr.link("add", ifname=bridge, kind="bridge")
            except NetlinkError as exc:
                if exc.code == errno.EEXIST:
                    return
                raise

    def _set_link_state(self, ifname: str, state: str, ignore_missing: bool) -> None:
        with IPRoute() as ipr:
            indexes = ipr.link_lookup(ifname=ifname)
            if not indexes:
                if ignore_missing:
                    return
                raise NetlinkError(errno.ENODEV, os.strerror(errno.ENODEV))
            ipr.link("set", index=indexes[0], state=state)

    def _set_master(self, tap_name: str, bridge: str) -> None:
        with IPRoute() as ipr:
            tap_idx = ipr.link_lookup(ifname=tap_name)
            bridge_idx = ipr.link_lookup(ifname=bridge)
            if not tap_idx:
                raise NetlinkError(errno.ENODEV, f"Tap {tap_name} not found")
            if not bridge_idx:
                raise NetlinkError(errno.ENODEV, f"Bridge {bridge} not found")
            ipr.link("set", index=tap_idx[0], master=bridge_idx[0])

    def _clear_master(self, tap_name: str) -> None:
        with IPRoute() as ipr:
            indexes = ipr.link_lookup(ifname=tap_name)
            if not indexes:
                return
            ipr.link("set", index=indexes[0], master=0)

    def _assign_address(self, ifname: str, address: str, cidr: int) -> None:
        with IPRoute() as ipr:
            indexes = ipr.link_lookup(ifname=ifname)
            if not indexes:
                raise NetlinkError(errno.ENODEV, f"Interface {ifname} not found")
            ipr.addr("replace", index=indexes[0], address=address, mask=cidr)

    def _remove_address(self, ifname: str, address: str, cidr: int) -> None:
        with IPRoute() as ipr:
            indexes = ipr.link_lookup(ifname=ifname)
            if not indexes:
                return
            try:
                ipr.addr("del", index=indexes[0], address=address, mask=cidr)
            except NetlinkError as exc:
                if exc.code in {errno.ENOENT, errno.EADDRNOTAVAIL, errno.ENODEV}:
                    return
                raise
