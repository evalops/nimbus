# Configuration Reference

This document aggregates the environment variables and helper tooling required to configure Nimbus services.

## Control Plane (`nimbus.control_plane`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_GITHUB_APP_ID` | GitHub App numeric identifier. | required |
| `NIMBUS_GITHUB_APP_PRIVATE_KEY` | PEM-encoded private key for the GitHub App. | required |
| `NIMBUS_GITHUB_APP_INSTALLATION_ID` | Installation ID for the GitHub App. | required |
| `NIMBUS_GITHUB_WEBHOOK_SECRET` | Shared secret for validating webhook signatures. | required |
| `NIMBUS_REDIS_URL` | Redis connection string (e.g. `redis://localhost:6379/0`). | required |
| `NIMBUS_DATABASE_URL` | Async SQLAlchemy database URL (e.g. `postgresql+asyncpg://user:pass@host/nimbus_control`). | required |
| `NIMBUS_JWT_SECRET` | Secret used to mint control-plane JWTs for CLI access. | required |
| `NIMBUS_PUBLIC_BASE_URL` | Public URL base returned to GitHub for runner callbacks. | required |
| `NIMBUS_METRICS_TOKEN` | Bearer token required for `/metrics`; if unset, access is restricted to loopback clients. | optional |
| `NIMBUS_CACHE_TOKEN_TTL` | Seconds before cache tokens expire. | `3600` |
| `NIMBUS_CACHE_SHARED_SECRET` | HMAC secret for cache token minting. | required |
| `NIMBUS_SSH_SESSION_SECRET` | HMAC secret used to mint and verify SSH debugging tokens. | `local-ssh-secret` |
| `NIMBUS_AGENT_TOKEN_SECRET` | Secret used to mint/verify agent bearer tokens. | required |
| `NIMBUS_AGENT_TOKEN_RATE_LIMIT` | Maximum agent token mint operations per interval. | `15` |
| `NIMBUS_AGENT_TOKEN_RATE_INTERVAL` | Interval window (seconds) for token mint rate limiting. | `60` |
| `NIMBUS_ADMIN_ALLOWED_SUBJECTS` | Comma-separated list of allowed admin JWT subjects. | empty (all subjects) |
| `NIMBUS_WEBHOOK_TIMESTAMP_TOLERANCE` | Allowed skew (seconds) for `X-Hub-Signature-Timestamp` values. | `300` |

## Host Agent (`nimbus.host_agent`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_AGENT_ID` | Unique identifier for the host agent instance. | required |
| `NIMBUS_CONTROL_PLANE_URL` | Base URL of the control plane API. | required |
| `NIMBUS_CONTROL_PLANE_TOKEN` | Bearer token issued by the control plane. | required |
| `NIMBUS_AGENT_REDIS_URL` | Optional Redis URL for local coordination/caching. | optional |
| `NIMBUS_CACHE_PROXY_URL` | Cache proxy base URL for artifact downloads. | optional |
| `NIMBUS_NEAR_CACHE_ENABLE` | Enable the embedded near-runner cache service. | `false` |
| `NIMBUS_NEAR_CACHE_DIR` | Filesystem root for near-runner cache data. | `/var/lib/nimbus/near-cache` |
| `NIMBUS_NEAR_CACHE_BIND` | Bind address for the FastAPI near-cache server. | `0.0.0.0` |
| `NIMBUS_NEAR_CACHE_ADVERTISE` | Host/IP advertised to jobs for cache access. | `127.0.0.1` |
| `NIMBUS_NEAR_CACHE_PORT` | Fixed port for the cache listener (random within range when unset). | unset |
| `NIMBUS_NEAR_CACHE_PORT_START` | Lower bound of random cache port allocation range. | `38000` |
| `NIMBUS_NEAR_CACHE_PORT_END` | Upper bound of random cache port allocation range. | `39000` |
| `NIMBUS_NEAR_CACHE_S3_BUCKET` | Optional S3 bucket for cache read-through/write-through. | unset |
| `NIMBUS_NEAR_CACHE_S3_ENDPOINT` | S3-compatible endpoint URL for cache fallbacks. | unset |
| `NIMBUS_NEAR_CACHE_S3_REGION` | Region identifier used with the cache S3 endpoint. | unset |
| `NIMBUS_NEAR_CACHE_S3_WRITE_THROUGH` | Enable uploading cached artifacts back to S3. | `false` |
| `NIMBUS_NEAR_CACHE_MOUNT_TAG` | Virtio-fs mount tag exposed to Firecracker guests. | `nimbus-cache` |
| `NIMBUS_NEAR_CACHE_MOUNT_PATH` | Mount path inside guests when virtio-fs is available. | `/mnt/nimbus-cache` |
| `NIMBUS_NEAR_CACHE_VIRTIOFSD` | Absolute path to the `virtiofsd` binary for guest mounts. | unset |
| `NIMBUS_AGENT_STATE_DATABASE_URL` | Async SQLAlchemy URL for the host agent state store. | `postgresql+asyncpg://localhost/nimbus_agent_state` |
| `NIMBUS_LOG_SINK_URL` | Logging pipeline ingest endpoint. | optional |
| `NIMBUS_AGENT_METRICS_HOST` | Prometheus metrics listener host. | `0.0.0.0` |
| `NIMBUS_AGENT_METRICS_PORT` | Prometheus metrics listener port. | `9460` |
| `NIMBUS_FC_BIN` | Path to the Firecracker binary. | `/usr/local/bin/firecracker` |
| `NIMBUS_KERNEL_IMAGE` | Path to kernel image used for VMs. | required |
| `NIMBUS_ROOTFS_IMAGE` | Root filesystem image path. | required |
| `NIMBUS_TAP_PREFIX` | Prefix for tap interfaces created per VM. | `nimbus` |
| `NIMBUS_JOB_TIMEOUT` | Maximum job runtime in seconds. | `3600` |
| `NIMBUS_VM_SHUTDOWN_GRACE` | Graceful shutdown wait in seconds. | `30` |
| `NIMBUS_AGENT_LEASE_RETRIES` | Number of retries for lease requests. | `3` |
| `NIMBUS_AGENT_LEASE_RETRY_BASE` | Base backoff delay (seconds). | `1.0` |
| `NIMBUS_AGENT_LEASE_RETRY_MAX` | Maximum backoff delay (seconds). | `15.0` |

## Cache Proxy (`nimbus.cache_proxy`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_CACHE_STORAGE_PATH` | Filesystem directory for cached artifacts. | `./cache` |
| `NIMBUS_CACHE_SHARED_SECRET` | HMAC secret for API token validation. | required |
| `NIMBUS_CACHE_S3_ENDPOINT` | S3-compatible endpoint URL. | optional |
| `NIMBUS_CACHE_S3_BUCKET` | S3 bucket/key prefix for remote storage. | optional |
| `NIMBUS_CACHE_S3_REGION` | AWS region for the S3 endpoint. | optional |
| `NIMBUS_CACHE_METRICS_DB` | SQLAlchemy database URL for cache metrics (Postgres recommended). | `postgresql+psycopg://localhost/nimbus_cache_metrics` |
| `NIMBUS_CACHE_METRICS_TOKEN` | Bearer token required for cache proxy metrics scraping. | optional |
| `NIMBUS_CACHE_S3_MAX_RETRIES` | Retry attempts for S3 operations. | `3` |
| `NIMBUS_CACHE_S3_RETRY_BASE` | Base backoff (seconds) for retries. | `0.2` |
| `NIMBUS_CACHE_S3_RETRY_MAX` | Maximum backoff (seconds). | `2.0` |
| `NIMBUS_CACHE_S3_CIRCUIT_FAILURES` | Failures before the circuit opens. | `5` |
| `NIMBUS_CACHE_S3_CIRCUIT_RESET` | Seconds before retrying after the circuit opens. | `30` |
| `NIMBUS_CACHE_MAX_BYTES` | Optional storage cap that triggers eviction of cold entries. | unset |
| `NIMBUS_CACHE_EVICTION_BATCH` | Number of cold entries inspected per eviction pass. | `100` |

## Docker Layer Cache (`nimbus.docker_cache`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_CACHE_SHARED_SECRET` | Shared secret reused for validating cache tokens. | required |
| `NIMBUS_DOCKER_CACHE_STORAGE_PATH` | Root directory for blob content. | `./docker-cache/blobs` |
| `NIMBUS_DOCKER_CACHE_UPLOAD_PATH` | Temporary upload staging directory. | `./docker-cache/uploads` |
| `NIMBUS_DOCKER_CACHE_DB_PATH` | SQLAlchemy database URL for Docker cache metadata (Postgres recommended). | `postgresql+psycopg://localhost/nimbus_docker_cache` |
| `NIMBUS_DOCKER_CACHE_MAX_BYTES` | Optional byte limit for on-disk blobs (0 disables). | `0` |

## Logging Pipeline (`nimbus.logging_pipeline`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_CLICKHOUSE_URL` | ClickHouse HTTP endpoint (e.g. `http://localhost:8123`). | required |
| `NIMBUS_CLICKHOUSE_DATABASE` | Target database name. | `nimbus` |
| `NIMBUS_CLICKHOUSE_TABLE` | Target table for log ingestion. | `ci_logs` |
| `NIMBUS_CLICKHOUSE_USERNAME` | Basic auth username for ClickHouse. | optional |
| `NIMBUS_CLICKHOUSE_PASSWORD` | Basic auth password for ClickHouse. | optional |
| `NIMBUS_CLICKHOUSE_TIMEOUT` | HTTP timeout in seconds for ClickHouse operations. | `10` |
| `NIMBUS_LOGGING_METRICS_TOKEN` | Bearer token required for logging pipeline metrics scraping. | optional |

## Web Dashboard (`web/`)

Vite environment variables are prefixed with `VITE_` and can be provided via `.env` in the `web/` directory or compose overrides.

| Variable | Description | Default |
| --- | --- | --- |
| `VITE_DEFAULT_CONTROL_PLANE_URL` | Base URL used when settings are blank. | unset (use compose default) |
| `VITE_DEFAULT_LOGGING_URL` | Optional logging endpoint default. | unset |

## Shared Observability Variables

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_LOG_LEVEL` | Structured logging level (`DEBUG`, `INFO`, etc.). | `INFO` |
| `NIMBUS_OTEL_EXPORTER_ENDPOINT` | OTLP collector endpoint (HTTP or gRPC). | console exporter |
| `NIMBUS_OTEL_EXPORTER_HEADERS` | Comma-separated OTLP headers (`key=value`). | none |
| `NIMBUS_OTEL_SAMPLER_RATIO` | Sampling ratio (0.0–1.0) for tracing. | `0.1` |

## Bootstrapping Utilities

- **Environment generation** – `uv run python scripts/bootstrap_compose.py --output .env` produces a populated `.env`. Add `--control-plane-url http://localhost:8000 --admin-token <jwt>` to mint an initial host agent token and `--secrets-output bootstrap-tokens.json` to capture minted tokens.
- **Manual setup** – copy `compose.env.sample` and populate values using the `nimbus.cli.admin` helpers.

## Developer Shortcuts

- Makefile targets: `make bootstrap`, `make compose-up`, `make compose-down`, `make test`, `make build-web`, `make lint-web`, `make build-docker-cache`
- `uv` equivalents: `uv run bootstrap`, `uv run compose-up`, `uv run test`
- Compose helper: `python scripts/compose_manager.py <command>` (supports `logs --follow`, profiles, etc.)

## Related Documents

- [Getting Started](./getting-started.md)
- [Operations](./operations.md)
- [Firecracker Security Hardening](./FIRECRACKER_SECURITY.md)
