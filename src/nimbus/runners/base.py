"""Base executor interface and common result types."""

from __future__ import annotations

import abc
from datetime import datetime
from typing import Optional, Protocol

from pydantic import BaseModel

from ..common.schemas import JobAssignment


class RunResult(BaseModel):
    """Result of a job execution."""
    
    success: bool
    exit_code: int
    log_lines: list[str] = []
    metrics: Optional[str] = None
    duration_seconds: Optional[float] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class Executor(Protocol):
    """Protocol defining the interface that all job executors must implement."""
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique name identifying this executor type."""
        ...
    
    @property
    @abc.abstractmethod
    def capabilities(self) -> list[str]:
        """List of capabilities this executor provides."""
        ...
    
    @abc.abstractmethod
    async def prepare(self, job: JobAssignment) -> None:
        """Prepare environment for job execution (network, volumes, etc.)."""
        ...
    
    @abc.abstractmethod
    async def run(
        self, 
        job: JobAssignment, 
        *, 
        timeout_seconds: Optional[int] = None,
        deadline: Optional[datetime] = None
    ) -> RunResult:
        """Execute the job and return the result."""
        ...
    
    @abc.abstractmethod
    async def cleanup(self, job_id: int) -> None:
        """Clean up resources associated with a job."""
        ...
