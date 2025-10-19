"""Performance monitoring and optimization for the executor system."""

from __future__ import annotations

import asyncio
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

import structlog

from ..common.metrics import GLOBAL_REGISTRY, Gauge, Counter, Histogram
from .base import RunResult

LOGGER = structlog.get_logger("nimbus.runners.performance")


@dataclass
class JobMetrics:
    """Performance metrics for a completed job."""
    
    job_id: int
    executor_name: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    exit_code: int
    success: bool
    cpu_usage: float = 0.0
    memory_peak_mb: float = 0.0
    warm_instance_used: bool = False


@dataclass
class ExecutorStats:
    """Aggregated statistics for an executor."""
    
    total_jobs: int = 0
    successful_jobs: int = 0
    failed_jobs: int = 0
    avg_duration: float = 0.0
    p95_duration: float = 0.0
    p99_duration: float = 0.0
    warm_hit_rate: float = 0.0  # % of jobs that used warm instances
    recent_durations: deque = field(default_factory=lambda: deque(maxlen=100))


class PerformanceMonitor:
    """Monitors and analyzes executor performance for optimization opportunities."""
    
    def __init__(self) -> None:
        self._job_metrics: List[JobMetrics] = []
        self._executor_stats: Dict[str, ExecutorStats] = defaultdict(ExecutorStats)
        self._active_jobs: Dict[int, datetime] = {}
        
        # Prometheus metrics
        self._job_duration_histogram = GLOBAL_REGISTRY.register(
            Histogram("nimbus_job_duration_seconds", 
                     [0.1, 0.5, 1.0, 5.0, 30.0, 60.0, 300.0, 600.0],
                     "Job execution duration")
        )
        self._executor_performance_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_executor_avg_duration_seconds", "Average job duration by executor")
        )
        self._warm_hit_rate_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_warm_instance_hit_rate", "Warm instance utilization rate")
        )
        self._executor_efficiency_gauge = GLOBAL_REGISTRY.register(
            Gauge("nimbus_executor_efficiency_ratio", "Success rate for executor")
        )
    
    def record_job_start(self, job_id: int) -> None:
        """Record when a job starts execution."""
        self._active_jobs[job_id] = datetime.now(timezone.utc)
    
    def record_job_completion(
        self, 
        job_id: int, 
        executor_name: str,
        result: RunResult,
        warm_instance_used: bool = False,
        cpu_usage: float = 0.0,
        memory_peak_mb: float = 0.0
    ) -> None:
        """Record job completion and update performance statistics."""
        start_time = self._active_jobs.pop(job_id, None)
        if not start_time:
            LOGGER.warning("No start time recorded for job", job_id=job_id)
            return
        
        finished_at = datetime.now(timezone.utc)
        duration_seconds = (finished_at - start_time).total_seconds()
        
        # Create job metrics
        metrics = JobMetrics(
            job_id=job_id,
            executor_name=executor_name,
            started_at=start_time,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
            exit_code=result.exit_code,
            success=result.success,
            cpu_usage=cpu_usage,
            memory_peak_mb=memory_peak_mb,
            warm_instance_used=warm_instance_used
        )
        
        self._job_metrics.append(metrics)
        
        # Update executor statistics
        self._update_executor_stats(metrics)
        
        # Update Prometheus metrics
        self._update_prometheus_metrics(metrics)
        
        LOGGER.info("Job performance recorded",
                   job_id=job_id,
                   executor=executor_name, 
                   duration=duration_seconds,
                   success=result.success,
                   warm_used=warm_instance_used)
    
    def _update_executor_stats(self, metrics: JobMetrics) -> None:
        """Update aggregated statistics for an executor."""
        stats = self._executor_stats[metrics.executor_name]
        
        stats.total_jobs += 1
        if metrics.success:
            stats.successful_jobs += 1
        else:
            stats.failed_jobs += 1
        
        # Update duration tracking
        stats.recent_durations.append(metrics.duration_seconds)
        
        # Recalculate aggregates
        durations = list(stats.recent_durations)
        if durations:
            stats.avg_duration = sum(durations) / len(durations)
            sorted_durations = sorted(durations)
            n = len(sorted_durations)
            stats.p95_duration = sorted_durations[int(n * 0.95)] if n > 0 else 0.0
            stats.p99_duration = sorted_durations[int(n * 0.99)] if n > 0 else 0.0
        
        # Calculate warm instance hit rate for recent jobs
        recent_jobs = [m for m in self._job_metrics[-100:] if m.executor_name == metrics.executor_name]
        if recent_jobs:
            warm_hits = sum(1 for job in recent_jobs if job.warm_instance_used)
            stats.warm_hit_rate = warm_hits / len(recent_jobs)
    
    def _update_prometheus_metrics(self, metrics: JobMetrics) -> None:
        """Update Prometheus metrics."""
        # Record job duration
        self._job_duration_histogram.observe(metrics.duration_seconds)
        
        # Update per-executor metrics
        stats = self._executor_stats[metrics.executor_name]
        self._executor_performance_gauge.set(stats.avg_duration)
        self._warm_hit_rate_gauge.set(stats.warm_hit_rate)
        
        # Calculate efficiency (success rate)
        efficiency = stats.successful_jobs / max(1, stats.total_jobs)
        self._executor_efficiency_gauge.set(efficiency)
    
    def get_executor_stats(self, executor_name: str) -> Optional[ExecutorStats]:
        """Get statistics for a specific executor."""
        return self._executor_stats.get(executor_name)
    
    def get_performance_recommendations(self) -> List[str]:
        """Analyze performance data and provide optimization recommendations."""
        recommendations = []
        
        for executor_name, stats in self._executor_stats.items():
            if stats.total_jobs < 5:
                continue  # Not enough data
            
            # Check for slow executors
            if stats.avg_duration > 60.0:
                recommendations.append(
                    f"⚠️  {executor_name}: Average duration {stats.avg_duration:.1f}s is high. "
                    f"Consider enabling warm pools or optimizing container images."
                )
            
            # Check warm pool utilization
            if stats.warm_hit_rate < 0.5 and executor_name == "firecracker":
                recommendations.append(
                    f"🏊 {executor_name}: Low warm pool hit rate ({stats.warm_hit_rate:.1%}). "
                    f"Consider increasing min_warm pool size."
                )
            
            # Check failure rate
            failure_rate = stats.failed_jobs / max(1, stats.total_jobs)
            if failure_rate > 0.1:  # More than 10% failures
                recommendations.append(
                    f"❌ {executor_name}: High failure rate ({failure_rate:.1%}). "
                    f"Check resource limits and image compatibility."
                )
            
            # Check for performance degradation
            recent_50 = list(stats.recent_durations)[-50:] if stats.recent_durations else []
            older_50 = list(stats.recent_durations)[:-50] if len(stats.recent_durations) > 50 else []
            
            if recent_50 and older_50:
                recent_avg = sum(recent_50) / len(recent_50)
                older_avg = sum(older_50) / len(older_50) 
                
                if recent_avg > older_avg * 1.5:  # 50% degradation
                    recommendations.append(
                        f"📉 {executor_name}: Performance degradation detected. "
                        f"Recent jobs {recent_avg:.1f}s vs historical {older_avg:.1f}s."
                    )
        
        return recommendations
    
    def get_performance_summary(self) -> dict:
        """Get a summary of overall system performance."""
        total_jobs = sum(stats.total_jobs for stats in self._executor_stats.values())
        total_successful = sum(stats.successful_jobs for stats in self._executor_stats.values())
        
        if total_jobs == 0:
            return {"message": "No jobs processed yet"}
        
        overall_success_rate = total_successful / total_jobs
        
        # Find fastest and slowest executors
        avg_durations = {
            name: stats.avg_duration 
            for name, stats in self._executor_stats.items() 
            if stats.total_jobs > 0
        }
        
        fastest = min(avg_durations.items(), key=lambda x: x[1]) if avg_durations else None
        slowest = max(avg_durations.items(), key=lambda x: x[1]) if avg_durations else None
        
        summary = {
            "total_jobs": total_jobs,
            "success_rate": f"{overall_success_rate:.1%}",
            "executors": len(self._executor_stats),
        }
        
        if fastest:
            summary["fastest_executor"] = f"{fastest[0]} ({fastest[1]:.1f}s avg)"
        
        if slowest:
            summary["slowest_executor"] = f"{slowest[0]} ({slowest[1]:.1f}s avg)"
        
        return summary
    
    def cleanup_old_metrics(self, days_to_keep: int = 7) -> None:
        """Clean up old metrics to prevent memory growth."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
        
        original_count = len(self._job_metrics)
        self._job_metrics = [
            m for m in self._job_metrics 
            if m.finished_at > cutoff
        ]
        
        removed = original_count - len(self._job_metrics)
        if removed > 0:
            LOGGER.info("Cleaned up old job metrics", removed=removed, kept=len(self._job_metrics))
