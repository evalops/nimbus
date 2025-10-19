"""Firecracker snapshot generation tool for fast boot times."""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import httpx
import structlog

from ..common.settings import HostAgentSettings
from ..host_agent.firecracker import FirecrackerLauncher, MicroVMNetwork

LOGGER = structlog.get_logger("nimbus.tools.snapshot_builder")


class SnapshotBuilder:
    """Tool to create Firecracker snapshots for fast boot."""
    
    def __init__(self, settings: HostAgentSettings) -> None:
        self._settings = settings
        self._launcher = FirecrackerLauncher(settings)
    
    async def create_golden_snapshot(
        self,
        output_state_path: Path,
        output_memory_path: Path,
        pre_boot_commands: list[str] | None = None,
    ) -> None:
        """Create a golden snapshot with base OS and common dependencies."""
        
        LOGGER.info("Creating golden snapshot", 
                   state_path=str(output_state_path),
                   memory_path=str(output_memory_path))
        
        with tempfile.TemporaryDirectory(prefix="nimbus-snapshot-") as workdir:
            workdir_path = Path(workdir)
            api_socket = workdir_path / "firecracker.sock"
            log_path = workdir_path / "firecracker.log"
            metrics_path = workdir_path / "firecracker.metrics"
            
            # Create a mock job ID for network allocation
            mock_job_id = 99999
            network = self._launcher.network_for_job(mock_job_id)
            
            try:
                # Prepare network and spawn Firecracker
                await self._launcher._prepare_network_resources(network)
                rootfs_copy, rootfs_hash = self._launcher._prepare_rootfs(workdir_path)
                
                process, context = await self._launcher._spawn_firecracker(
                    api_socket, log_path, metrics_path, rootfs_copy, rootfs_hash, network
                )
                
                # Wait for Firecracker API to be ready
                await self._wait_for_api(context)
                
                # Configure the microVM 
                await self._configure_microvm(context, network, rootfs_copy)
                
                # Start the VM and let it boot
                await self._start_and_boot(context)
                
                # Execute pre-boot commands if provided
                if pre_boot_commands:
                    await self._execute_pre_boot_commands(context, pre_boot_commands)
                
                # Create the snapshot
                await self._create_snapshot(context, output_state_path, output_memory_path)
                
                LOGGER.info("Golden snapshot created successfully")
                
            finally:
                # Cleanup
                if process and process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=10)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
                
                await self._launcher.cleanup_network(network)
    
    async def _wait_for_api(self, context, timeout: int = 30) -> None:
        """Wait for Firecracker API to be ready."""
        transport = httpx.AsyncHTTPTransport(uds=str(context.api_socket_host))
        
        for attempt in range(timeout):
            try:
                async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
                    response = await client.get("/")
                    if response.status_code in (200, 404):  # API is ready
                        return
            except Exception:
                pass
            
            await asyncio.sleep(1)
        
        raise RuntimeError("Firecracker API did not become ready in time")
    
    async def _configure_microvm(self, context, network: MicroVMNetwork, rootfs_path: Path) -> None:
        """Configure the microVM via API."""
        transport = httpx.AsyncHTTPTransport(uds=str(context.api_socket_host))
        
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            # Configure boot source
            await self._put(client, "/boot-source", {
                "kernel_image_path": context.kernel_guest_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro",
            })
            
            # Configure rootfs drive
            await self._put(client, "/drives/rootfs", {
                "drive_id": "rootfs",
                "path_on_host": context.rootfs_guest_path,
                "is_root_device": True,
                "is_read_only": True,
            })
            
            # Configure machine
            await self._put(client, "/machine-config", {
                "vcpu_count": 2,
                "mem_size_mib": 2048,  # Smaller for snapshot
                "ht_enabled": False,
            })
            
            # Configure network
            if network:
                await self._put(client, "/network-interfaces/eth0", {
                    "iface_id": "eth0",
                    "guest_mac": self._launcher._guest_mac_for_tap(network.tap_name),
                    "host_dev_name": network.tap_name,
                })
    
    async def _start_and_boot(self, context, boot_timeout: int = 15) -> None:
        """Start the VM and wait for it to boot."""
        transport = httpx.AsyncHTTPTransport(uds=str(context.api_socket_host))
        
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            # Start the instance
            await self._put(client, "/actions", {"action_type": "InstanceStart"})
            
            LOGGER.info("Waiting for VM to boot...")
            await asyncio.sleep(boot_timeout)  # Wait for boot to complete
    
    async def _execute_pre_boot_commands(self, context, commands: list[str]) -> None:
        """Execute commands in the booted VM before snapshotting."""
        # This would require a way to execute commands in the VM
        # For now, we'll just log that we would execute them
        LOGGER.info("Pre-boot commands to execute", commands=commands)
        # In a full implementation, this might use guest agents or SSH
    
    async def _create_snapshot(
        self, 
        context, 
        state_path: Path, 
        memory_path: Path
    ) -> None:
        """Create the snapshot files."""
        transport = httpx.AsyncHTTPTransport(uds=str(context.api_socket_host))
        
        # Ensure output directories exist
        state_path.parent.mkdir(parents=True, exist_ok=True)
        memory_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            # Pause the VM
            await self._put(client, "/vm", {"state": "Paused"})
            
            # Create snapshot
            await self._put(client, "/snapshot/create", {
                "snapshot_path": str(state_path),
                "memory_file_path": str(memory_path),
            })
            
            LOGGER.info("Snapshot files created", 
                       state=str(state_path),
                       memory=str(memory_path))
    
    async def _put(self, client: httpx.AsyncClient, path: str, payload: dict) -> None:
        """Make a PUT request to Firecracker API."""
        response = await client.put(path, json=payload)
        if response.status_code >= 400:
            raise RuntimeError(f"API {path} failed: {response.status_code} {response.text}")


async def main():
    """CLI entry point for snapshot creation."""
    import os
    from argparse import ArgumentParser
    
    parser = ArgumentParser(description="Create Firecracker snapshots")
    parser.add_argument("--state-path", required=True, type=Path)
    parser.add_argument("--memory-path", required=True, type=Path)
    parser.add_argument("--pre-boot-cmd", action="append", default=[])
    
    args = parser.parse_args()
    
    # Set up minimal environment
    os.environ.setdefault("NIMBUS_AGENT_ID", "snapshot-builder")
    os.environ.setdefault("NIMBUS_CONTROL_PLANE_URL", "http://localhost:8000")
    os.environ.setdefault("NIMBUS_CONTROL_PLANE_TOKEN", "unused")
    
    settings = HostAgentSettings()
    builder = SnapshotBuilder(settings)
    
    await builder.create_golden_snapshot(
        args.state_path,
        args.memory_path,
        args.pre_boot_cmd or None,
    )


if __name__ == "__main__":
    asyncio.run(main())
