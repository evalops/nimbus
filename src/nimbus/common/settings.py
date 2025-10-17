"""Application configuration models shared by services."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field, HttpUrl, RedisDsn, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def env_field(default, env_name: str):
    return Field(default, validation_alias=env_name)


class ControlPlaneSettings(BaseSettings):
    """Runtime settings for the control plane API service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    github_app_id: int = env_field(..., "NIMBUS_GITHUB_APP_ID")
    github_app_private_key: SecretStr = env_field(..., "NIMBUS_GITHUB_APP_PRIVATE_KEY")
    github_app_installation_id: int = env_field(..., "NIMBUS_GITHUB_APP_INSTALLATION_ID")
    github_webhook_secret: SecretStr = env_field(..., "NIMBUS_GITHUB_WEBHOOK_SECRET")
    redis_url: RedisDsn = env_field(..., "NIMBUS_REDIS_URL")
    database_url: str = env_field(..., "NIMBUS_DATABASE_URL")
    jwt_secret: SecretStr = env_field(..., "NIMBUS_JWT_SECRET")
    jwt_secret_fallbacks: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_JWT_SECRET_FALLBACKS",
    )
    public_base_url: HttpUrl = env_field(..., "NIMBUS_PUBLIC_BASE_URL")
    cache_token_ttl_seconds: int = env_field(3600, "NIMBUS_CACHE_TOKEN_TTL")
    cache_shared_secret: SecretStr = env_field(..., "NIMBUS_CACHE_SHARED_SECRET")
    agent_token_secret: SecretStr = env_field(..., "NIMBUS_AGENT_TOKEN_SECRET")
    agent_token_secret_fallbacks: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_AGENT_TOKEN_SECRET_FALLBACKS",
    )
    agent_token_rate_limit: int = env_field(15, "NIMBUS_AGENT_TOKEN_RATE_LIMIT")
    agent_token_rate_interval_seconds: int = env_field(60, "NIMBUS_AGENT_TOKEN_RATE_INTERVAL")
    webhook_timestamp_tolerance_seconds: int = env_field(300, "NIMBUS_WEBHOOK_TIMESTAMP_TOLERANCE")
    org_job_rate_limit: int = env_field(100, "NIMBUS_ORG_JOB_RATE_LIMIT")
    org_rate_interval_seconds: int = env_field(60, "NIMBUS_ORG_RATE_INTERVAL")
    job_lease_ttl_seconds: int = env_field(300, "NIMBUS_JOB_LEASE_TTL")
    metrics_token: Optional[SecretStr] = env_field(None, "NIMBUS_METRICS_TOKEN")
    admin_allowed_subjects: list[str] = Field(default_factory=list, validation_alias="NIMBUS_ADMIN_ALLOWED_SUBJECTS")
    admin_allowed_ips: list[str] = Field(default_factory=list, validation_alias="NIMBUS_ADMIN_ALLOWED_IPS")
    trusted_proxy_cidrs: list[str] = Field(default_factory=list, validation_alias="NIMBUS_TRUSTED_PROXY_CIDRS")
    admin_rate_limit: int = env_field(60, "NIMBUS_ADMIN_RATE_LIMIT")
    admin_rate_interval_seconds: int = env_field(60, "NIMBUS_ADMIN_RATE_INTERVAL")
    require_https: bool = env_field(False, "NIMBUS_REQUIRE_HTTPS")
    ssh_port_range_start: int = env_field(22000, "NIMBUS_SSH_PORT_START")
    ssh_port_range_end: int = env_field(22100, "NIMBUS_SSH_PORT_END")
    ssh_session_default_ttl: int = env_field(900, "NIMBUS_SSH_SESSION_TTL")
    log_level: str = env_field("INFO", "NIMBUS_LOG_LEVEL")
    otel_exporter_endpoint: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_ENDPOINT")
    otel_exporter_headers: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_HEADERS")
    otel_sampler_ratio: float = env_field(0.1, "NIMBUS_OTEL_SAMPLER_RATIO")
    offline_mode: bool = env_field(False, "NIMBUS_OFFLINE_MODE")
    allowed_artifact_registries: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_ALLOWED_ARTIFACT_REGISTRIES",
    )
    metadata_endpoint_denylist: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_METADATA_DENYLIST",
    )
    egress_policy_pack: Optional[Path] = env_field(None, "NIMBUS_EGRESS_POLICY_PACK")
    saml_sp_entity_id: Optional[str] = env_field(None, "NIMBUS_SAML_SP_ENTITY_ID")
    saml_assertion_consumer_service_url: Optional[HttpUrl] = env_field(
        None,
        "NIMBUS_SAML_ACS_URL",
    )
    saml_idp_metadata_path: Optional[Path] = env_field(None, "NIMBUS_SAML_IDP_METADATA")
    saml_sp_certificate_path: Optional[Path] = env_field(None, "NIMBUS_SAML_SP_CERT")
    saml_sp_private_key_path: Optional[Path] = env_field(None, "NIMBUS_SAML_SP_KEY")
    saml_default_program_id: Optional[str] = env_field(None, "NIMBUS_SAML_DEFAULT_PROGRAM")
    sso_session_secret: Optional[SecretStr] = env_field(None, "NIMBUS_SSO_SESSION_SECRET")
    scim_token: Optional[SecretStr] = env_field(None, "NIMBUS_SCIM_TOKEN")
    program_policy_path: Optional[Path] = env_field(None, "NIMBUS_PROGRAM_POLICY_PATH")
    service_account_default_ttl_seconds: int = env_field(3600, "NIMBUS_SERVICE_ACCOUNT_TTL")
    compliance_matrix_path: Optional[Path] = env_field(None, "NIMBUS_COMPLIANCE_MATRIX")
    itar_permitted_regions: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_ITAR_REGIONS",
    )
    itar_export_log_retention_days: int = env_field(365, "NIMBUS_ITAR_EXPORT_LOG_RETENTION")
    ca_bundle_path: Optional[Path] = env_field(None, "NIMBUS_CA_BUNDLE")

    @field_validator("admin_allowed_subjects", mode="before")
    @classmethod
    def _split_admin_subjects(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("allowed_artifact_registries", mode="before")
    @classmethod
    def _split_allowed_registries(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("metadata_endpoint_denylist", mode="before")
    @classmethod
    def _split_metadata_denylist(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("itar_permitted_regions", mode="before")
    @classmethod
    def _split_itar_regions(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("admin_allowed_ips", mode="before")
    @classmethod
    def _split_admin_ips(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def _split_proxy_cidrs(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("agent_token_secret_fallbacks", mode="before")
    @classmethod
    def _split_agent_token_fallbacks(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("jwt_secret_fallbacks", mode="before")
    @classmethod
    def _split_jwt_fallbacks(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def agent_token_secrets(self) -> list[str]:
        return [self.agent_token_secret.get_secret_value(), *self.agent_token_secret_fallbacks]

    @property
    def jwt_secrets(self) -> list[str]:
        primary = (
            self.jwt_secret.get_secret_value()
            if hasattr(self.jwt_secret, "get_secret_value")
            else str(self.jwt_secret)
        )
        return [primary, *self.jwt_secret_fallbacks]


class HostAgentSettings(BaseSettings):
    """Configuration for the host agent daemon."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    agent_id: str = env_field(..., "NIMBUS_AGENT_ID")
    control_plane_base_url: HttpUrl = env_field(..., "NIMBUS_CONTROL_PLANE_URL")
    control_plane_token: SecretStr = env_field(..., "NIMBUS_CONTROL_PLANE_TOKEN")
    redis_url: Optional[RedisDsn] = env_field(None, "NIMBUS_AGENT_REDIS_URL")
    log_sink_url: Optional[HttpUrl] = env_field(None, "NIMBUS_LOG_SINK_URL")
    metrics_host: str = env_field("127.0.0.1", "NIMBUS_AGENT_METRICS_HOST")
    metrics_port: int = env_field(9460, "NIMBUS_AGENT_METRICS_PORT")
    cache_proxy_url: Optional[HttpUrl] = env_field(None, "NIMBUS_CACHE_PROXY_URL")
    state_database_url: str = env_field(
        "postgresql+asyncpg://localhost/nimbus_agent_state",
        "NIMBUS_AGENT_STATE_DATABASE_URL",
    )

    firecracker_bin_path: str = env_field("/usr/local/bin/firecracker", "NIMBUS_FC_BIN")
    jailer_bin_path: Optional[str] = env_field(None, "NIMBUS_JAILER_BIN")
    jailer_uid: int = env_field(1000, "NIMBUS_JAILER_UID")
    jailer_gid: int = env_field(1000, "NIMBUS_JAILER_GID")
    jailer_chroot_base: Path = env_field(Path("/srv/jailer"), "NIMBUS_JAILER_CHROOT_BASE")
    seccomp_filter_path: Optional[Path] = env_field(None, "NIMBUS_SECCOMP_FILTER")
    kernel_image_path: str = env_field(..., "NIMBUS_KERNEL_IMAGE")
    rootfs_image_path: str = env_field(..., "NIMBUS_ROOTFS_IMAGE")
    rootfs_manifest_path: Optional[Path] = env_field(None, "NIMBUS_ROOTFS_MANIFEST")
    rootfs_version: Optional[str] = env_field(None, "NIMBUS_ROOTFS_VERSION")
    require_rootfs_attestation: bool = env_field(False, "NIMBUS_ROOTFS_ATTESTATION_REQUIRED")
    snapshot_state_path: Optional[str] = env_field(None, "NIMBUS_SNAPSHOT_STATE_PATH")
    snapshot_memory_path: Optional[str] = env_field(None, "NIMBUS_SNAPSHOT_MEMORY_PATH")
    snapshot_enable_diff: bool = env_field(False, "NIMBUS_SNAPSHOT_ENABLE_DIFF")
    tap_device_prefix: str = env_field("nimbus", "NIMBUS_TAP_PREFIX")
    enable_network_namespaces: bool = env_field(True, "NIMBUS_ENABLE_NETNS")
    net_rate_limit_rx_bytes_per_sec: Optional[int] = env_field(50 * 1024 * 1024, "NIMBUS_NET_RX_BPS")
    net_rate_limit_tx_bytes_per_sec: Optional[int] = env_field(50 * 1024 * 1024, "NIMBUS_NET_TX_BPS")
    net_rate_limit_burst_bytes: Optional[int] = env_field(5 * 1024 * 1024, "NIMBUS_NET_BURST_BYTES")
    cpu_affinity: list[int] = Field(default_factory=list, validation_alias="NIMBUS_CPU_AFFINITY")
    job_timeout_seconds: int = env_field(3600, "NIMBUS_JOB_TIMEOUT")
    vm_shutdown_grace_seconds: int = env_field(30, "NIMBUS_VM_SHUTDOWN_GRACE")
    lease_retry_attempts: int = env_field(3, "NIMBUS_AGENT_LEASE_RETRIES")
    lease_retry_base_seconds: float = env_field(1.0, "NIMBUS_AGENT_LEASE_RETRY_BASE")
    lease_retry_max_seconds: float = env_field(15.0, "NIMBUS_AGENT_LEASE_RETRY_MAX")
    log_level: str = env_field("INFO", "NIMBUS_LOG_LEVEL")
    otel_exporter_endpoint: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_ENDPOINT")
    otel_exporter_headers: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_HEADERS")
    otel_sampler_ratio: float = env_field(0.1, "NIMBUS_OTEL_SAMPLER_RATIO")
    enable_ssh: bool = env_field(False, "NIMBUS_SSH_ENABLE")
    ssh_poll_interval_seconds: float = env_field(5.0, "NIMBUS_SSH_POLL_INTERVAL")
    ssh_authorized_key: Optional[str] = env_field(None, "NIMBUS_SSH_AUTHORIZED_KEY")
    offline_mode: bool = env_field(False, "NIMBUS_AGENT_OFFLINE_MODE")
    metadata_endpoint_denylist: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_AGENT_METADATA_DENYLIST",
    )
    artifact_registry_allow_list: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_AGENT_REGISTRY_ALLOW",
    )
    artifact_registry_deny_list: list[str] = Field(
        default_factory=list,
        validation_alias="NIMBUS_AGENT_REGISTRY_DENY",
    )
    egress_policy_pack: Optional[Path] = env_field(None, "NIMBUS_AGENT_EGRESS_POLICY_PACK")
    image_allow_list_path: Optional[Path] = env_field(None, "NIMBUS_AGENT_IMAGE_ALLOW_LIST")
    image_deny_list_path: Optional[Path] = env_field(None, "NIMBUS_AGENT_IMAGE_DENY_LIST")
    sbom_output_path: Optional[Path] = env_field(None, "NIMBUS_AGENT_SBOM_OUTPUT")
    cosign_certificate_authority: Optional[Path] = env_field(None, "NIMBUS_AGENT_COSIGN_CA")
    provenance_required: bool = env_field(True, "NIMBUS_AGENT_PROVENANCE_REQUIRED")

    @field_validator("cpu_affinity", mode="before")
    @classmethod
    def _split_cpu_affinity(cls, value):
        if isinstance(value, str):
            entries = []
            for item in value.split(","):
                item = item.strip()
                if not item:
                    continue
                entries.append(int(item))
            return entries
        return value

    @field_validator("metadata_endpoint_denylist", mode="before")
    @classmethod
    def _split_metadata_denylist(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("artifact_registry_allow_list", mode="before")
    @classmethod
    def _split_registry_allow(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("artifact_registry_deny_list", mode="before")
    @classmethod
    def _split_registry_deny(cls, value):
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


class CacheProxySettings(BaseSettings):
    """Configuration for the cache proxy service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", populate_by_name=True)
    storage_path: Path = env_field(Path("./cache"), "NIMBUS_CACHE_STORAGE_PATH")
    shared_secret: SecretStr = env_field(SecretStr("local-cache-secret"), "NIMBUS_CACHE_SHARED_SECRET")
    metrics_token: Optional[SecretStr] = env_field(None, "NIMBUS_CACHE_METRICS_TOKEN")
    s3_endpoint_url: Optional[str] = env_field(None, "NIMBUS_CACHE_S3_ENDPOINT")
    s3_bucket: Optional[str] = env_field(None, "NIMBUS_CACHE_S3_BUCKET")
    s3_region: Optional[str] = env_field(None, "NIMBUS_CACHE_S3_REGION")
    metrics_database_url: str = env_field(
        "postgresql+psycopg://localhost/nimbus_cache_metrics",
        "NIMBUS_CACHE_METRICS_DB",
    )
    org_storage_quota_bytes: Optional[int] = env_field(None, "NIMBUS_CACHE_ORG_QUOTA_BYTES")
    s3_max_retries: int = env_field(3, "NIMBUS_CACHE_S3_MAX_RETRIES")
    s3_retry_base_seconds: float = env_field(0.2, "NIMBUS_CACHE_S3_RETRY_BASE")
    s3_retry_max_seconds: float = env_field(2.0, "NIMBUS_CACHE_S3_RETRY_MAX")
    s3_circuit_breaker_failures: int = env_field(5, "NIMBUS_CACHE_S3_CIRCUIT_FAILURES")
    s3_circuit_breaker_reset_seconds: float = env_field(30.0, "NIMBUS_CACHE_S3_CIRCUIT_RESET")
    max_storage_bytes: Optional[int] = env_field(None, "NIMBUS_CACHE_MAX_BYTES")
    max_artifact_bytes: int = env_field(100 * 1024 * 1024, "NIMBUS_CACHE_MAX_ARTIFACT_BYTES")  # 100MB default
    cache_eviction_batch_size: int = env_field(100, "NIMBUS_CACHE_EVICTION_BATCH")
    log_level: str = env_field("INFO", "NIMBUS_LOG_LEVEL")
    otel_exporter_endpoint: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_ENDPOINT")
    otel_exporter_headers: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_HEADERS")
    otel_sampler_ratio: float = env_field(0.1, "NIMBUS_OTEL_SAMPLER_RATIO")

    @field_validator("metrics_database_url", mode="before")
    @classmethod
    def _normalize_metrics_url(cls, value):
        if isinstance(value, Path):
            value = str(value)
        if isinstance(value, str) and "://" not in value:
            path = Path(value).expanduser().resolve()
            return f"sqlite+pysqlite:///{path.as_posix()}"
        return value


class LoggingIngestSettings(BaseSettings):
    """Settings for the log ingestion service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    clickhouse_url: HttpUrl = env_field(..., "NIMBUS_CLICKHOUSE_URL")
    clickhouse_database: str = env_field("nimbus", "NIMBUS_CLICKHOUSE_DATABASE")
    clickhouse_table: str = env_field("ci_logs", "NIMBUS_CLICKHOUSE_TABLE")
    clickhouse_username: Optional[str] = env_field(None, "NIMBUS_CLICKHOUSE_USERNAME")
    clickhouse_password: Optional[str] = env_field(None, "NIMBUS_CLICKHOUSE_PASSWORD")
    clickhouse_timeout_seconds: int = env_field(10, "NIMBUS_CLICKHOUSE_TIMEOUT")
    metrics_token: Optional[SecretStr] = env_field(None, "NIMBUS_LOGGING_METRICS_TOKEN")
    log_query_max_hours: int = env_field(168, "NIMBUS_LOG_QUERY_MAX_HOURS")  # 7 days default
    shared_secret: SecretStr = env_field(SecretStr("local-cache-secret"), "NIMBUS_CACHE_SHARED_SECRET")
    log_level: str = env_field("INFO", "NIMBUS_LOG_LEVEL")
    otel_exporter_endpoint: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_ENDPOINT")
    otel_exporter_headers: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_HEADERS")
    otel_sampler_ratio: float = env_field(0.1, "NIMBUS_OTEL_SAMPLER_RATIO")


class DockerCacheSettings(BaseSettings):
    """Configuration for the Docker layer cache registry service."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    storage_path: Path = env_field(Path("./docker-cache"), "NIMBUS_DOCKER_CACHE_STORAGE_PATH")
    uploads_path: Path = env_field(Path("./docker-cache/uploads"), "NIMBUS_DOCKER_CACHE_UPLOAD_PATH")
    metadata_database_url: str = env_field(
        "postgresql+psycopg://localhost/nimbus_docker_cache",
        "NIMBUS_DOCKER_CACHE_DB_PATH",
    )
    shared_secret: SecretStr = env_field(SecretStr("local-cache-secret"), "NIMBUS_CACHE_SHARED_SECRET")
    max_storage_bytes: Optional[int] = env_field(None, "NIMBUS_DOCKER_CACHE_MAX_BYTES")
    org_storage_quota_bytes: Optional[int] = env_field(None, "NIMBUS_DOCKER_ORG_QUOTA_BYTES")
    log_level: str = env_field("INFO", "NIMBUS_LOG_LEVEL")
    otel_exporter_endpoint: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_ENDPOINT")
    otel_exporter_headers: Optional[str] = env_field(None, "NIMBUS_OTEL_EXPORTER_HEADERS")
    otel_sampler_ratio: float = env_field(0.1, "NIMBUS_OTEL_SAMPLER_RATIO")

    @field_validator("metadata_database_url", mode="before")
    @classmethod
    def _normalize_metadata_url(cls, value):
        if isinstance(value, Path):
            value = str(value)
        if isinstance(value, str) and "://" not in value:
            path = Path(value).expanduser().resolve()
            return f"sqlite+pysqlite:///{path.as_posix()}"
        return value

