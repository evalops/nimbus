"""Application configuration models shared by services."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseSettings, Field, HttpUrl, RedisDsn


class ControlPlaneSettings(BaseSettings):
    """Runtime settings for the control plane API service."""

    github_app_id: int = Field(..., env="SMITH_GITHUB_APP_ID")
    github_app_private_key: str = Field(..., env="SMITH_GITHUB_APP_PRIVATE_KEY")
    github_app_installation_id: int = Field(..., env="SMITH_GITHUB_APP_INSTALLATION_ID")
    redis_url: RedisDsn = Field(..., env="SMITH_REDIS_URL")
    database_url: str = Field(..., env="SMITH_DATABASE_URL")
    jwt_secret: str = Field(..., env="SMITH_JWT_SECRET")
    public_base_url: HttpUrl = Field(..., env="SMITH_PUBLIC_BASE_URL")
    cache_token_ttl_seconds: int = Field(3600, env="SMITH_CACHE_TOKEN_TTL")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class HostAgentSettings(BaseSettings):
    """Configuration for the host agent daemon."""

    agent_id: str = Field(..., env="SMITH_AGENT_ID")
    control_plane_base_url: HttpUrl = Field(..., env="SMITH_CONTROL_PLANE_URL")
    control_plane_token: str = Field(..., env="SMITH_CONTROL_PLANE_TOKEN")
    redis_url: Optional[RedisDsn] = Field(None, env="SMITH_AGENT_REDIS_URL")
    cache_proxy_url: Optional[HttpUrl] = Field(None, env="SMITH_CACHE_PROXY_URL")
    log_sink_url: Optional[HttpUrl] = Field(None, env="SMITH_LOG_SINK_URL")

    firecracker_bin_path: str = Field("/usr/local/bin/firecracker", env="SMITH_FC_BIN")
    kernel_image_path: str = Field(..., env="SMITH_KERNEL_IMAGE")
    rootfs_image_path: str = Field(..., env="SMITH_ROOTFS_IMAGE")
    tap_device_prefix: str = Field("smith", env="SMITH_TAP_PREFIX")
    job_timeout_seconds: int = Field(3600, env="SMITH_JOB_TIMEOUT")
    vm_shutdown_grace_seconds: int = Field(30, env="SMITH_VM_SHUTDOWN_GRACE")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class CacheProxySettings(BaseSettings):
    """Configuration for the cache proxy service."""

    storage_path: Path = Field(..., env="SMITH_CACHE_STORAGE_PATH")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class LoggingIngestSettings(BaseSettings):
    """Settings for the log ingestion service."""

    clickhouse_url: HttpUrl = Field(..., env="SMITH_CLICKHOUSE_URL")
    clickhouse_database: str = Field("smith", env="SMITH_CLICKHOUSE_DATABASE")
    clickhouse_table: str = Field("ci_logs", env="SMITH_CLICKHOUSE_TABLE")
    clickhouse_username: Optional[str] = Field(None, env="SMITH_CLICKHOUSE_USERNAME")
    clickhouse_password: Optional[str] = Field(None, env="SMITH_CLICKHOUSE_PASSWORD")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
