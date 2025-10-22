"""Resource tracking and cgroup management for job executors."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List

import structlog

from ..common.metrics import GLOBAL_REGISTRY, Gauge, Counter

LOGGER = structlog.get_logger("nimbus.runners.resource_manager")


@dataclass
class ResourceUsage:
    """Resource usage metrics for a job or executor."""
    
    cpu_seconds: float = 0.0
    memory_bytes: int = 0
    max_memory_bytes: int = 0
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0


class CGroupManager:
    """Manages cgroup v2 slices for resource tracking and limiting."""
    
    def __init__(self, cgroup_root: Path = Path("/sys/fs/cgroup")) -> None:
        self._cgroup_root = cgroup_root
        self._nimbus_slice = cgroup_root / "nimbus-jobs.slice"
        self._active_jobs: Dict[int, Path] = {}
        
        # Metrics (labels will be provided at metric update time)
        self._cpu_usage_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_job_cpu_seconds_total", "CPU time used by job")
        )
        self._memory_usage_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_job_memory_bytes", "Memory used by job")
        )
        self._io_read_counter = GLOBAL_REGISTRY.register(
            Counter("nimbus_job_io_read_bytes_total", "IO read by job")
        )
        self._io_write_counter = GLOBAL_REGISTRY.register(
            Counter("nimbus_job_io_write_bytes_total", "IO write by job")
        )
    
    async def initialize(self) -> None:
        """Initialize the cgroup hierarchy."""
        if not self._cgroup_root.exists():
            LOGGER.warning("cgroup v2 not available", path=str(self._cgroup_root))
            return
            
        try:
            # Create nimbus jobs slice if it doesn't exist
            self._nimbus_slice.mkdir(exist_ok=True)
            
            # Enable controllers
            controllers_file = self._nimbus_slice / "cgroup.subtree_control"
            if controllers_file.exists():
                controllers_file.write_text("+cpu +memory +io")
                LOGGER.info("Initialized cgroup v2 slice", slice=str(self._nimbus_slice))
            else:
                LOGGER.warning("Cannot enable cgroup controllers - may need root privileges")
                
        except Exception as exc:
            LOGGER.warning("cgroup initialization failed", error=str(exc))
    
    async def create_job_cgroup(
        self, 
        job_id: int, 
        executor_name: str,
        cpu_limit: Optional[float] = None,
        memory_limit_mb: Optional[int] = None
    ) -> Optional[Path]:
        """Create a cgroup for a job with optional resource limits."""
        if not self._nimbus_slice.exists():
            return None
            
        job_cgroup = self._nimbus_slice / f"job-{job_id}.scope"
        
        try:
            job_cgroup.mkdir(exist_ok=True)
            self._active_jobs[job_id] = job_cgroup
            
            # Set CPU limit if specified
            if cpu_limit:
                cpu_max = job_cgroup / "cpu.max"
                if cpu_max.exists():
                    # Convert CPU limit to period/quota (100ms period)
                    period = 100000  # 100ms in microseconds
                    quota = int(cpu_limit * period)
                    cpu_max.write_text(f"{quota} {period}")
            
            # Set memory limit if specified
            if memory_limit_mb:
                memory_max = job_cgroup / "memory.max"
                if memory_max.exists():
                    memory_max.write_text(str(memory_limit_mb * 1024 * 1024))
            
            LOGGER.info("Created job cgroup", 
                       job_id=job_id,
                       cgroup=str(job_cgroup),
                       cpu_limit=cpu_limit,
                       memory_limit_mb=memory_limit_mb)
            
            return job_cgroup
            
        except Exception as exc:
            LOGGER.warning("Failed to create job cgroup", 
                          job_id=job_id, 
                          error=str(exc))
            return None
    
    async def add_pid_to_job(self, job_id: int, pid: int) -> bool:
        """Add a process to the job's cgroup."""
        job_cgroup = self._active_jobs.get(job_id)
        if not job_cgroup or not job_cgroup.exists():
            return False
            
        try:
            cgroup_procs = job_cgroup / "cgroup.procs"
            cgroup_procs.write_text(str(pid))
            LOGGER.debug("Added process to job cgroup", job_id=job_id, pid=pid)
            return True
        except Exception as exc:
            LOGGER.warning("Failed to add PID to cgroup", 
                          job_id=job_id, 
                          pid=pid,
                          error=str(exc))
            return False
    
    async def get_job_usage(self, job_id: int) -> Optional[ResourceUsage]:
        """Get current resource usage for a job."""
        job_cgroup = self._active_jobs.get(job_id)
        if not job_cgroup or not job_cgroup.exists():
            return None
            
        try:
            usage = ResourceUsage()
            
            # CPU usage
            cpu_stat = job_cgroup / "cpu.stat"
            if cpu_stat.exists():
                cpu_data = cpu_stat.read_text()
                for line in cpu_data.strip().split('\n'):
                    if line.startswith('usage_usec '):
                        usage.cpu_seconds = int(line.split()[1]) / 1_000_000
                        break
            
            # Memory usage
            memory_current = job_cgroup / "memory.current"
            if memory_current.exists():
                usage.memory_bytes = int(memory_current.read_text().strip())
            
            memory_peak = job_cgroup / "memory.peak"
            if memory_peak.exists():
                usage.max_memory_bytes = int(memory_peak.read_text().strip())
            
            # IO usage
            io_stat = job_cgroup / "io.stat"
            if io_stat.exists():
                io_data = io_stat.read_text()
                for line in io_data.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 3:
                        for stat in parts[1:]:
                            if stat.startswith('rbytes='):
                                usage.io_read_bytes += int(stat.split('=')[1])
                            elif stat.startswith('wbytes='):
                                usage.io_write_bytes += int(stat.split('=')[1])
            
            return usage
            
        except Exception as exc:
            LOGGER.warning("Failed to read job resource usage", 
                          job_id=job_id,
                          error=str(exc))
            return None
    
    async def cleanup_job_cgroup(self, job_id: int) -> None:
        """Clean up the cgroup for a completed job."""
        job_cgroup = self._active_jobs.pop(job_id, None)
        if not job_cgroup or not job_cgroup.exists():
            return
            
        try:
            # Kill any remaining processes in the cgroup
            cgroup_procs = job_cgroup / "cgroup.procs"
            if cgroup_procs.exists():
                pids = cgroup_procs.read_text().strip().split('\n')
                for pid_str in pids:
                    if pid_str:
                        try:
                            pid = int(pid_str)
                            os.kill(pid, 9)  # SIGKILL
                        except (ValueError, ProcessLookupError):
                            pass
            
            # Remove the cgroup directory
            job_cgroup.rmdir()
            LOGGER.debug("Cleaned up job cgroup", job_id=job_id)
            
        except Exception as exc:
            LOGGER.warning("Failed to cleanup job cgroup", 
                          job_id=job_id,
                          error=str(exc))
    
    async def update_metrics(self, job_id: int, executor_name: str) -> Optional[ResourceUsage]:
        """Update Prometheus metrics for a job."""
        usage = await self.get_job_usage(job_id)
        if not usage:
            return None

        labels = [str(job_id), executor_name]
        self._cpu_usage_gauge.set(usage.cpu_seconds, labels=labels)
        self._memory_usage_gauge.set(usage.memory_bytes, labels=labels)

        # Counters need to track deltas, but for simplicity we'll just use current values
        # In production, we'd track previous values and report deltas
        return usage


class ResourceTracker:
    """High-level resource tracking and monitoring for executors."""
    
    def __init__(self) -> None:
        self._cgroup_manager = CGroupManager()
        self._tracking_tasks: Dict[int, asyncio.Task] = {}
        self._running = False
        self._usage_history: Dict[int, List[dict[str, float | str]]] = {}
    
    async def start(self) -> None:
        """Start the resource tracking system."""
        self._running = True
        try:
            await self._cgroup_manager.initialize()
            LOGGER.info("Resource tracker started")
        except Exception as e:
            LOGGER.warning("Failed to initialize cgroup manager", error=str(e))
            # Continue running without cgroup support
    
    async def stop(self) -> None:
        """Stop the resource tracking system."""
        self._running = False
        
        # Cancel all tracking tasks
        for task in list(self._tracking_tasks.values()):
            task.cancel()
        
        if self._tracking_tasks:
            await asyncio.gather(*self._tracking_tasks.values(), return_exceptions=True)
        
        LOGGER.info("Resource tracker stopped")
    
    async def start_job_tracking(
        self, 
        job_id: int, 
        executor_name: str,
        pid: Optional[int] = None,
        cpu_limit: Optional[float] = None,
        memory_limit_mb: Optional[int] = None
    ) -> None:
        """Start resource tracking for a job."""
        if not self._running:
            return
            
        # Create cgroup
        cgroup_path = await self._cgroup_manager.create_job_cgroup(
            job_id, executor_name, cpu_limit, memory_limit_mb
        )
        
        if cgroup_path and pid:
            await self._cgroup_manager.add_pid_to_job(job_id, pid)
        
        # Start metrics tracking task
        task = asyncio.create_task(
            self._track_job_metrics(job_id, executor_name)
        )
        self._tracking_tasks[job_id] = task
        task.add_done_callback(lambda t: self._tracking_tasks.pop(job_id, None))
    
    async def stop_job_tracking(self, job_id: int) -> None:
        """Stop resource tracking for a job."""
        # Cancel metrics task
        task = self._tracking_tasks.pop(job_id, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Clean up cgroup
        await self._cgroup_manager.cleanup_job_cgroup(job_id)
        self._usage_history.pop(job_id, None)
    
    async def add_process(self, job_id: int, pid: int) -> None:
        """Add a process to job tracking."""
        await self._cgroup_manager.add_pid_to_job(job_id, pid)
    
    async def get_usage(self, job_id: int) -> Optional[ResourceUsage]:
        """Get resource usage for a job."""
        return await self._cgroup_manager.get_job_usage(job_id)

    def get_usage_history(self, job_id: int) -> List[dict[str, float | str]]:
        return list(self._usage_history.get(job_id, []))
    
    async def _track_job_metrics(self, job_id: int, executor_name: str) -> None:
        """Periodically update metrics for a job."""
        while self._running:
            try:
                usage = await self._cgroup_manager.update_metrics(job_id, executor_name)
                if usage:
                    history = self._usage_history.setdefault(job_id, [])
                    history.append(
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "cpu_seconds": usage.cpu_seconds,
                            "memory_bytes": usage.memory_bytes,
                        }
                    )
                    if len(history) > 120:
                        history.pop(0)
            except Exception as exc:
                LOGGER.warning("Metrics update failed",
                              job_id=job_id,
                              error=str(exc))

            await asyncio.sleep(5)  # Update every 5 seconds
