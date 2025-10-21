"""Shared data models for the simplified Blacksmith-inspired system."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class GitHubRepository(BaseModel):
    """Repository metadata extracted from GitHub webhook payloads."""

    id: int
    name: str
    full_name: str
    private: bool = False
    html_url: Optional[HttpUrl] = None
    owner_id: Optional[int] = None


class GitHubWorkflowJob(BaseModel):
    """Subset of workflow_job payload we care about for scheduling."""

    id: int
    run_id: int
    run_attempt: int = 1
    status: Literal["queued", "in_progress", "completed"]
    labels: list[str] = Field(default_factory=list)
    runner_group_id: Optional[int] = None
    runner_name: Optional[str] = None
    head_sha: Optional[str] = None
    workflow_name: Optional[str] = None
    display_title: Optional[str] = None


class WebhookWorkflowJobEvent(BaseModel):
    """Parsed GitHub webhook for workflow_job events."""

    action: Literal["queued", "in_progress", "completed", "waiting"]
    repository: GitHubRepository
    workflow_job: GitHubWorkflowJob


class RunnerRegistrationToken(BaseModel):
    """Registration token issued by GitHub for a single use runner."""

    token: str
    expires_at: datetime


class CacheToken(BaseModel):
    """Token scoped per organization to authorize cache access."""

    token: str
    organization_id: int
    expires_at: datetime
    scope: str = "read_write"  # Format: "read:org-123,write:org-123" or "read_write"


class JobAssignment(BaseModel):
    """Payload delivered to host agents for execution."""

    job_id: int
    run_id: int
    run_attempt: int
    repository: GitHubRepository
    labels: list[str]
    runner_registration: RunnerRegistrationToken
    cache_token: Optional[CacheToken] = None
    executor: str = "firecracker"  # Which executor to use
    payload_received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str] = Field(default_factory=dict)


class JobLeaseRequest(BaseModel):
    """Request sent by host agents to lease the next queued job."""

    agent_id: str
    agent_version: str
    capabilities: list[str] = Field(default_factory=list)


class JobLeaseResponse(BaseModel):
    """Response containing either job details or an idle directive."""

    job: Optional[JobAssignment] = None
    fence_token: Optional[int] = None
    lease_ttl_seconds: int = 300
    backoff_seconds: int = 5


class JobStatusUpdate(BaseModel):
    """Status reported back from host agent once job state changes."""

    agent_id: str
    job_id: int
    status: Literal["starting", "running", "succeeded", "failed", "cancelled"]
    message: Optional[str] = None
    fence_token: Optional[int] = None
    reported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class JobRecord(BaseModel):
    """Job record returned by the control plane."""

    job_id: int
    run_id: int
    run_attempt: int
    repo_id: int
    repo_full_name: str
    repo_private: bool
    org_id: Optional[int] = None
    labels: list[str]
    status: str
    agent_id: Optional[str] = None
    executor: str = "firecracker"
    queued_at: datetime
    leased_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_message: Optional[str] = None
    updated_at: datetime
    metadata: dict[str, str] = Field(default_factory=dict)


class JobMetadataRecord(BaseModel):
    job_id: int
    run_id: int
    run_attempt: int
    org_id: int
    repo_id: int
    key: str
    value: str
    executor: Optional[str] = None
    status: Optional[str] = None
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class JobMetadataBatch(BaseModel):
    records: list[JobMetadataRecord]
    metadata: dict[str, str] = Field(default_factory=dict)


class LogEntry(BaseModel):
    """Log record emitted by a job or microVM."""

    job_id: int
    agent_id: str
    org_id: Optional[int] = None
    repo_id: Optional[int] = None
    level: Literal["debug", "info", "warning", "error", "critical"] = "info"
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LogIngestRequest(BaseModel):
    """Batch of log entries sent to the logging pipeline."""

    entries: list[LogEntry]


class AgentTokenMintRequest(BaseModel):
    agent_id: str
    ttl_seconds: int = Field(ge=60, default=3600)


class AgentTokenResponse(BaseModel):
    agent_id: str
    token: str
    expires_at: datetime
    ttl_seconds: int
    version: int


class AgentTokenRecord(BaseModel):
    agent_id: str
    token_version: int
    rotated_at: datetime
    ttl_seconds: int


class AgentTokenAuditRecord(BaseModel):
    id: int
    agent_id: str
    rotated_by: str
    token_version: int
    rotated_at: datetime
    ttl_seconds: int


class SSHSessionRequest(BaseModel):
    """Admin request to open an SSH session for a running job."""

    job_id: int
    ttl_seconds: int = Field(default=900, ge=60, le=3600)
    authorized_user: str = Field(default="runner", max_length=128)


class SSHSession(BaseModel):
    """SSH session metadata returned by the control plane."""

    session_id: str
    job_id: int
    agent_id: str
    host_port: int
    authorized_user: str
    status: Literal["pending", "active", "closed", "failed", "expired"]
    created_at: datetime
    expires_at: datetime
    vm_ip: Optional[str] = None
    reason: Optional[str] = None


class SSHSessionActivation(BaseModel):
    """Payload provided by host agents when activating a session."""

    vm_ip: str


class SSHSessionCloseRequest(BaseModel):
    """Payload supplied when closing an SSH session."""

    reason: Optional[str] = None


class JobLeaseRenewalRequest(BaseModel):
    """Request to renew a job lease."""

    job_id: int
    agent_id: str
    fence_token: int
