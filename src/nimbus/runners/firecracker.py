"""Firecracker-based executor implementation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from ..host_agent.firecracker import FirecrackerError, FirecrackerLauncher, MicroVMNetwork
from .base import Executor, RunResult


class FirecrackerExecutor:
    """Executor that runs jobs in Firecracker microVMs."""
    
    def __init__(self, settings: Optional[HostAgentSettings] = None) -> None:
        self._settings = settings
        self._launcher: Optional[FirecrackerLauncher] = None
        self._job_networks: dict[int, MicroVMNetwork] = {}
    
    def initialize(self, settings: HostAgentSettings) -> None:
        """Initialize the executor with settings."""
        self._settings = settings
        self._launcher = FirecrackerLauncher(settings)
    
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
