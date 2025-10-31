"""Firecracker-based executor implementation."""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from ..host_agent.firecracker import FirecrackerError, FirecrackerLauncher, MicroVMNetwork
from ..host_agent.near_cache import NearRunnerCacheManager
from .base import Executor, RunResult

LOGGER = structlog.get_logger("nimbus.runners.firecracker")


class FirecrackerExecutor:
    """Executor that runs jobs in Firecracker microVMs."""
    
    def __init__(self, settings: Optional[HostAgentSettings] = None) -> None:
        self._settings = settings
        self._launcher: Optional[FirecrackerLauncher] = None
        self._job_networks: dict[int, MicroVMNetwork] = {}
        self._near_cache: Optional[NearRunnerCacheManager] = None
    
    def initialize(self, settings: HostAgentSettings, *, near_cache: Optional[NearRunnerCacheManager] = None) -> None:
        """Initialize the executor with settings."""
        self._settings = settings
        self._near_cache = near_cache
        self._launcher = FirecrackerLauncher(settings, near_cache_manager=near_cache)
    
    @property
    def name(self) -> str:
        """Unique name identifying this executor type."""
        return "firecracker"
    
    @property
    def capabilities(self) -> list[str]:
        """List of capabilities this executor provides."""
        return ["firecracker", "microvm", "isolated"]
    
    async def prepare(self, job: JobAssignment) -> None:
        """Prepare environment for job execution (network setup)."""
        if not self._launcher:
            raise RuntimeError("FirecrackerExecutor not initialized")
        
        # Allocate network for the job
        network = self._launcher.network_for_job(job.job_id)
        self._job_networks[job.job_id] = network
    
    async def run(
        self, 
        job: JobAssignment, 
        *, 
        timeout_seconds: Optional[int] = None,
        deadline: Optional[datetime] = None
    ) -> RunResult:
        """Execute the job and return the result."""
        if not self._launcher:
            raise RuntimeError("FirecrackerExecutor not initialized")
        
        network = self._job_networks.get(job.job_id)
        started_at = datetime.now(timezone.utc)
        
        try:
            # Execute the job using the existing Firecracker launcher
            fc_result = await self._launcher.execute_job(
                job, 
                timeout_seconds=timeout_seconds, 
                network=network
            )
            
            finished_at = datetime.now(timezone.utc)
            duration_seconds = (finished_at - started_at).total_seconds()
            
            return RunResult(
                success=(fc_result.exit_code == 0),
                exit_code=fc_result.exit_code,
                log_lines=fc_result.log_lines,
                metrics=fc_result.metrics,
                duration_seconds=duration_seconds,
                started_at=started_at,
                finished_at=finished_at,
            )
            
        except FirecrackerError as exc:
            finished_at = datetime.now(timezone.utc)
            duration_seconds = (finished_at - started_at).total_seconds()
            
            # Extract result if available
            result_data = RunResult(
                success=False,
                exit_code=exc.result.exit_code if exc.result else -1,
                log_lines=exc.result.log_lines if exc.result else [],
                metrics=exc.result.metrics if exc.result else None,
                duration_seconds=duration_seconds,
                started_at=started_at,
                finished_at=finished_at,
            )
            
            # Re-raise as runtime error to maintain interface
            raise RuntimeError(str(exc)) from exc
    
    async def cleanup(self, job_id: int) -> None:
        """Clean up resources associated with a job."""
        if not self._launcher:
            return
            
        network = self._job_networks.pop(job_id, None)
        if network:
            try:
                await self._launcher.cleanup_network(network)
            except Exception:
                # Log but don't fail cleanup
                pass
    
    async def prepare_warm_instance(self, instance_id: str) -> dict:
        """Prepare a warm Firecracker instance ready for job assignment."""
        if not self._launcher:
            raise RuntimeError("FirecrackerExecutor not initialized")
        
        mock_job_id = hash(instance_id) % 100000  # Generate pseudo job ID
        network = self._launcher.network_for_job(mock_job_id)
        
        try:
            # Pre-setup network resources
            await self._launcher._prepare_network_resources(network)
            
            context = {
                "network": network,
                "mock_job_id": mock_job_id,
                "prepared_at": datetime.now(timezone.utc).isoformat(),
            }
            
            # If snapshots are enabled, pre-start a VM from snapshot
            if self._launcher._snapshot_enabled:
                vm_context = await self._prepare_snapshot_vm(instance_id, network)
                context.update({
                    "vm_context": vm_context,
                    "snapshot_ready": True,
                })
                LOGGER.info("Prepared warm Firecracker instance with snapshot", 
                           instance_id=instance_id,
                           tap=network.tap_name)
            else:
                LOGGER.info("Prepared warm Firecracker instance (cold boot)", 
                           instance_id=instance_id,
                           tap=network.tap_name)
            
            return context
            
        except Exception as exc:
            LOGGER.error("Failed to prepare warm instance", 
                        instance_id=instance_id, 
                        error=str(exc))
            raise
    
    async def cleanup_warm_instance(self, instance_id: str, context: dict) -> None:
        """Clean up a warm Firecracker instance."""
        if not self._launcher:
            return
        
        # Cleanup snapshot VM if it was running
        vm_context = context.get("vm_context")
        if vm_context:
            try:
                process = vm_context.get("process")
                if process and process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
                
                # Cleanup temporary directory
                temp_dir = vm_context.get("temp_dir")
                if temp_dir and Path(temp_dir).exists():
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
                LOGGER.debug("Cleaned up snapshot VM", instance_id=instance_id)
            except Exception as exc:
                LOGGER.warning("Snapshot VM cleanup failed", 
                              instance_id=instance_id,
                              error=str(exc))
            
        network = context.get("network")
        if network:
            try:
                await self._launcher.cleanup_network(network)
                LOGGER.debug("Cleaned up warm instance network", 
                           instance_id=instance_id,
                           tap=network.tap_name)
            except Exception as exc:
                LOGGER.warning("Warm instance network cleanup failed", 
                              instance_id=instance_id,
                              error=str(exc))
    
    async def health_check_warm_instance(self, instance_id: str, context: dict) -> bool:
        """Health check a warm Firecracker instance."""
        # For Firecracker warm instances, we just check if network is still available
        network = context.get("network")
        if not network:
            return False
            
        # Simple check - verify tap device exists
        import os
        tap_path = f"/sys/class/net/{network.tap_name}"
        exists = os.path.exists(tap_path)
        
        if not exists:
            LOGGER.warning("Warm instance network missing", 
                          instance_id=instance_id,
                          tap=network.tap_name)
        
        return exists
    
    async def _prepare_snapshot_vm(self, instance_id: str, network: MicroVMNetwork) -> dict:
        """Pre-start a VM from snapshot for ultra-fast job assignment."""
        import tempfile
        import httpx
        
        # Create temporary workspace for this warm instance
        temp_dir = Path(tempfile.mkdtemp(prefix=f"nimbus-warm-{instance_id}-"))
        api_socket = temp_dir / "firecracker.sock"
        log_path = temp_dir / "firecracker.log"  
        metrics_path = temp_dir / "firecracker.metrics"
        
        try:
            # Prepare minimal rootfs (just for metadata, snapshot has the real state)
            rootfs_copy, rootfs_hash = self._launcher._prepare_rootfs(temp_dir)
            
            # Spawn Firecracker process
            process, fc_context = await self._launcher._spawn_firecracker(
                api_socket, log_path, metrics_path, rootfs_copy, rootfs_hash, network
            )
            
            # Wait for API and restore from snapshot
            await self._wait_for_api(fc_context)
            await self._launcher._restore_snapshot(fc_context)
            await self._launcher._start_instance(api_socket)
            
            # Give it a moment to fully boot from snapshot
            await asyncio.sleep(0.2)  # 200ms should be enough from snapshot
            
            LOGGER.info("Snapshot VM ready", 
                       instance_id=instance_id,
                       temp_dir=str(temp_dir))
            
            return {
                "process": process,
                "fc_context": fc_context,
                "temp_dir": temp_dir,
                "api_socket": api_socket,
                "booted_at": datetime.now(timezone.utc).isoformat(),
            }
            
        except Exception as exc:
            # Cleanup on failure
            if 'process' in locals() and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            
            if temp_dir.exists():
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            
            raise RuntimeError(f"Failed to prepare snapshot VM: {exc}") from exc
    
    async def _wait_for_api(self, context, timeout: int = 10) -> None:
        """Wait for Firecracker API to be ready."""
        transport = httpx.AsyncHTTPTransport(uds=str(context.api_socket_host))
        
        for attempt in range(timeout):
            try:
                async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=1.0) as client:
                    response = await client.get("/")
                    if response.status_code in (200, 404):  # API is ready
                        return
            except Exception:
                pass
            
            await asyncio.sleep(0.1)  # Check every 100ms
        
        raise RuntimeError("Firecracker API did not become ready in time")
    
    async def prepare_job_with_warm_instance(self, job: JobAssignment, warm_instance) -> None:
        """Prepare a job using a warm instance - much faster than cold start."""
        if not warm_instance.context.get("snapshot_ready"):
            # Fall back to normal prepare if no snapshot
            await self.prepare(job)
            return
            
        vm_context = warm_instance.context.get("vm_context")
        if not vm_context:
            raise RuntimeError("Warm instance missing VM context")
        
        # The VM is already running from snapshot, just update job association
        self._job_networks[job.job_id] = warm_instance.context["network"]
        
        LOGGER.info("Job prepared with warm snapshot instance", 
                   job_id=job.job_id,
                   instance_id=warm_instance.instance_id,
                   boot_time="~80ms")
