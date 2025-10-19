"""Warm pool management for executors to reduce cold-start latency."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Set
from datetime import datetime, timezone

import structlog

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from .base import Executor, RunResult

LOGGER = structlog.get_logger("nimbus.runners.pool_manager")


@dataclass
class WarmInstance:
    """Represents a warm, pre-started executor instance ready for job assignment."""
    
    instance_id: str
    executor_name: str
    created_at: datetime
    last_health_check: Optional[datetime] = None
    is_healthy: bool = True
    reserved_for_job: Optional[int] = None  # Job ID if reserved
    context: dict = field(default_factory=dict)  # Executor-specific context


@dataclass 
class PoolConfig:
    """Configuration for a specific executor pool."""
    
    executor_name: str
    min_warm: int = 2
    max_warm: int = 5
    max_idle_seconds: int = 300  # 5 minutes
    health_check_interval: int = 60  # 1 minute
    creation_timeout: int = 30  # 30 seconds


class PoolManager:
    """Manages warm pools of executor instances to reduce job startup latency."""
    
    def __init__(self, settings: HostAgentSettings, executors: dict[str, Executor]) -> None:
        self._settings = settings
        self._executors = executors
        self._pools: Dict[str, Dict[str, WarmInstance]] = defaultdict(dict)
        self._pool_configs: Dict[str, PoolConfig] = {}
        self._next_instance_id = 0
        self._pool_tasks: Set[asyncio.Task] = set()
        self._running = False
        
        # Default pool configurations
        self._configure_default_pools()
    
    def _configure_default_pools(self) -> None:
        """Set up default pool configurations for available executors."""
        for executor_name in self._executors.keys():
            if executor_name == "firecracker":
                # Firecracker benefits most from warm pools due to slow boot
                self._pool_configs[executor_name] = PoolConfig(
                    executor_name=executor_name,
                    min_warm=1,  # Keep at least 1 warm VM
                    max_warm=3,  # Don't exceed 3 warm VMs
                    max_idle_seconds=600,  # 10 minutes for VMs
                    health_check_interval=30,  # Check every 30 seconds
                )
            elif executor_name == "docker":
                # Docker is already fast, smaller pool
                self._pool_configs[executor_name] = PoolConfig(
                    executor_name=executor_name,
                    min_warm=0,  # No minimum for Docker
                    max_warm=2,  # Small pool
                    max_idle_seconds=180,  # 3 minutes
                    health_check_interval=60,
                )
    
    async def start(self) -> None:
        """Start the pool manager and warm pool maintenance tasks."""
        if self._running:
            return
            
        self._running = True
        LOGGER.info("Starting pool manager")
        
        # Start pool maintenance tasks for each configured executor
        for config in self._pool_configs.values():
            task = asyncio.create_task(self._maintain_pool(config))
            self._pool_tasks.add(task)
            task.add_done_callback(self._pool_tasks.discard)
    
    async def stop(self) -> None:
        """Stop the pool manager and cleanup all warm instances."""
        LOGGER.info("Stopping pool manager")
        self._running = False
        
        # Cancel maintenance tasks
        for task in list(self._pool_tasks):
            task.cancel()
        
        if self._pool_tasks:
            await asyncio.gather(*self._pool_tasks, return_exceptions=True)
        
        # Cleanup all warm instances
        for executor_name, instances in self._pools.items():
            for instance in list(instances.values()):
                await self._destroy_instance(instance)
    
    async def get_warm_instance(self, executor_name: str, job: JobAssignment) -> Optional[WarmInstance]:
        """Get a warm executor instance for the specified job, if available."""
        if not self._running or executor_name not in self._pools:
            return None
        
        pool = self._pools[executor_name]
        
        # Find an available warm instance
        for instance in pool.values():
            if instance.reserved_for_job is None and instance.is_healthy:
                # Reserve this instance for the job
                instance.reserved_for_job = job.job_id
                LOGGER.info("Reserved warm instance", 
                           instance_id=instance.instance_id, 
                           job_id=job.job_id,
                           executor=executor_name)
                return instance
        
        LOGGER.debug("No warm instances available", executor=executor_name, pool_size=len(pool))
        return None
    
    async def release_instance(self, instance: WarmInstance, job_id: int) -> None:
        """Release a warm instance back to the pool or destroy it if unhealthy."""
        if instance.reserved_for_job != job_id:
            LOGGER.warning("Instance release mismatch", 
                          instance_id=instance.instance_id,
                          expected_job=job_id, 
                          actual_job=instance.reserved_for_job)
        
        instance.reserved_for_job = None
        
        # Check if instance should be returned to pool or destroyed
        if not instance.is_healthy:
            LOGGER.info("Destroying unhealthy instance", instance_id=instance.instance_id)
            await self._destroy_instance(instance)
        else:
            LOGGER.debug("Returned instance to pool", instance_id=instance.instance_id)
    
    async def _maintain_pool(self, config: PoolConfig) -> None:
        """Maintain a warm pool for the specified executor."""
        LOGGER.info("Starting pool maintenance", executor=config.executor_name)
        
        while self._running:
            try:
                await self._pool_maintenance_cycle(config)
            except Exception as exc:
                LOGGER.error("Pool maintenance error", 
                           executor=config.executor_name, 
                           error=str(exc))
            
            # Wait before next maintenance cycle
            await asyncio.sleep(config.health_check_interval)
    
    async def _pool_maintenance_cycle(self, config: PoolConfig) -> None:
        """Run a single pool maintenance cycle."""
        pool = self._pools[config.executor_name]
        now = datetime.now(timezone.utc)
        
        # Count healthy, available instances
        available_instances = [
            instance for instance in pool.values()
            if instance.is_healthy and instance.reserved_for_job is None
        ]
        
        # Remove stale/unhealthy instances
        for instance_id, instance in list(pool.items()):
            # Check for expired idle instances
            idle_seconds = (now - instance.created_at).total_seconds()
            if (instance.reserved_for_job is None and 
                idle_seconds > config.max_idle_seconds):
                LOGGER.info("Destroying idle instance", 
                           instance_id=instance_id,
                           idle_seconds=idle_seconds)
                await self._destroy_instance(instance)
                continue
            
            # Health check
            if not await self._health_check_instance(instance):
                instance.is_healthy = False
                if instance.reserved_for_job is None:
                    LOGGER.info("Destroying unhealthy instance", instance_id=instance_id)
                    await self._destroy_instance(instance)
        
        # Create new instances if below minimum
        available_count = len(available_instances)
        if available_count < config.min_warm:
            needed = config.min_warm - available_count
            LOGGER.info("Creating warm instances", 
                       executor=config.executor_name,
                       needed=needed,
                       current=available_count)
            
            for _ in range(needed):
                if len(pool) >= config.max_warm:
                    break
                await self._create_warm_instance(config)
    
    async def _create_warm_instance(self, config: PoolConfig) -> Optional[WarmInstance]:
        """Create a new warm executor instance."""
        executor = self._executors.get(config.executor_name)
        if not executor:
            LOGGER.error("Executor not found", executor=config.executor_name)
            return None
        
        instance_id = f"{config.executor_name}-{self._next_instance_id}"
        self._next_instance_id += 1
        
        try:
            instance = WarmInstance(
                instance_id=instance_id,
                executor_name=config.executor_name,
                created_at=datetime.now(timezone.utc),
            )
            
            # Executor-specific warm instance preparation
            if hasattr(executor, 'prepare_warm_instance'):
                context = await executor.prepare_warm_instance(instance_id)
                instance.context = context
            
            self._pools[config.executor_name][instance_id] = instance
            
            LOGGER.info("Created warm instance", 
                       instance_id=instance_id,
                       executor=config.executor_name)
            
            return instance
            
        except Exception as exc:
            LOGGER.error("Failed to create warm instance", 
                        instance_id=instance_id,
                        executor=config.executor_name,
                        error=str(exc))
            return None
    
    async def _destroy_instance(self, instance: WarmInstance) -> None:
        """Destroy a warm executor instance and clean up resources."""
        pool = self._pools[instance.executor_name]
        pool.pop(instance.instance_id, None)
        
        # Executor-specific cleanup
        executor = self._executors.get(instance.executor_name)
        if executor and hasattr(executor, 'cleanup_warm_instance'):
            try:
                await executor.cleanup_warm_instance(instance.instance_id, instance.context)
            except Exception as exc:
                LOGGER.error("Warm instance cleanup failed", 
                           instance_id=instance.instance_id,
                           error=str(exc))
        
        LOGGER.debug("Destroyed warm instance", instance_id=instance.instance_id)
    
    async def _health_check_instance(self, instance: WarmInstance) -> bool:
        """Perform health check on a warm executor instance."""
        if instance.reserved_for_job is not None:
            # Skip health check for reserved instances
            return True
        
        executor = self._executors.get(instance.executor_name)
        if not executor:
            return False
        
        # Executor-specific health check
        if hasattr(executor, 'health_check_warm_instance'):
            try:
                is_healthy = await executor.health_check_warm_instance(
                    instance.instance_id, 
                    instance.context
                )
                instance.last_health_check = datetime.now(timezone.utc)
                return is_healthy
            except Exception as exc:
                LOGGER.warning("Health check failed", 
                              instance_id=instance.instance_id,
                              error=str(exc))
                return False
        
        # Default health check - just mark as healthy if no specific check
        instance.last_health_check = datetime.now(timezone.utc)
        return True
    
    def get_pool_stats(self) -> dict[str, dict]:
        """Get current statistics for all pools."""
        stats = {}
        for executor_name, pool in self._pools.items():
            available = sum(1 for i in pool.values() 
                          if i.is_healthy and i.reserved_for_job is None)
            reserved = sum(1 for i in pool.values() if i.reserved_for_job is not None)
            unhealthy = sum(1 for i in pool.values() if not i.is_healthy)
            
            stats[executor_name] = {
                "total": len(pool),
                "available": available,
                "reserved": reserved,
                "unhealthy": unhealthy,
                "config": {
                    "min_warm": self._pool_configs[executor_name].min_warm,
                    "max_warm": self._pool_configs[executor_name].max_warm,
                }
            }
        
        return stats
