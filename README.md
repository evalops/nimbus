# Smith

Smith is an experimental platform that mirrors key ideas from Blacksmith.sh: an AWS-hosted control plane that orchestrates GitHub Actions jobs onto bare-metal hosts running Firecracker microVMs. This repository contains a prototype implementation that can be used as a learning tool or homelab foundation.

## Components
- **Control Plane (FastAPI):** Receives GitHub webhooks (with signature verification), issues runner registration tokens, and queues jobs in Redis.
- **Host Agent:** Polls the control plane for work, manages Firecracker microVMs, and forwards Firecracker logs to the logging pipeline when configured.
- Ensure host agents have permissions to create tap devices and bridges (requires `ip`/`iproute2`).
- **Cache Proxy:** Provides a simple artifact cache API backed by the filesystem or an S3-compatible endpoint (MinIO/Ceph) with HMAC-signed tokens.
- **Logging Pipeline:** Streams job logs into ClickHouse using JSONEachRow inserts.
- **Optional SSH/DNS Helpers:** Command snippets for exposing live SSH sessions and registering VM hostnames.

## Getting Started
1. Install dependencies with [uv](https://github.com/astral-sh/uv):
   ```bash
   uv venv .venv
   uv pip install -e .
   ```
2. Define environment variables for the control plane, host agent, cache proxy, and logging pipeline services (see inline comments in the settings classes for required keys, including `SMITH_GITHUB_WEBHOOK_SECRET`, `SMITH_AGENT_TOKEN_SECRET`, and `SMITH_CACHE_SHARED_SECRET`).
3. Launch services with uvicorn (example):
   ```bash
   uvicorn smith.control_plane.main:app --reload
   uvicorn smith.cache_proxy.main:app --reload --port 8001
   uvicorn smith.logging_pipeline.main:app --reload --port 8002
   python -m smith.host_agent.main
   ```
4. Optionally provide a fallback cache token to hosts via `SMITH_CACHE_TOKEN_SECRET` and `SMITH_CACHE_TOKEN_VALUE` when experimenting without live control-plane minted tokens.
5. Inspect recent jobs from the command line (example):
   ```bash
   python -m smith.cli.jobs recent --base-url http://localhost:8000 --token $SMITH_JWT_SECRET --limit 10
   ```
6. Check overall queue health:
   ```bash
   python -m smith.cli.jobs status --base-url http://localhost:8000 --token $SMITH_JWT_SECRET
   ```
7. Query logs for a job:
   ```bash
   python -m smith.cli.logs --logs-url http://localhost:8002 --job-id 12345 --limit 50
   ```
8. Mint a cache token for testing:
   ```bash
   python -m smith.cli.cache --secret $SMITH_CACHE_SHARED_SECRET --org-id 123 --ttl 3600
   ```
9. Mint an agent token for a host:
   ```bash
   python -m smith.cli.auth --agent-id agent-001 --secret $SMITH_AGENT_TOKEN_SECRET --ttl 3600
   ```
10. Run the unit and integration test suite:
    ```bash
    uv run pytest
    ```

## Environment Variables

### Control Plane (`smith.control_plane`)

| Variable | Description | Default |
| --- | --- | --- |
| `SMITH_GITHUB_APP_ID` | GitHub App numeric identifier. | required |
| `SMITH_GITHUB_APP_PRIVATE_KEY` | PEM-encoded private key for the GitHub App. | required |
| `SMITH_GITHUB_APP_INSTALLATION_ID` | Installation ID for the GitHub App. | required |
| `SMITH_GITHUB_WEBHOOK_SECRET` | Shared secret for validating webhook signatures. | required |
| `SMITH_REDIS_URL` | Redis connection string (e.g. `redis://localhost:6379/0`). | required |
| `SMITH_DATABASE_URL` | SQLAlchemy async database URL (e.g. `sqlite+aiosqlite:///./smith.db`). | required |
| `SMITH_JWT_SECRET` | Secret used to mint control-plane JWTs for CLI access. | required |
| `SMITH_PUBLIC_BASE_URL` | Public URL base returned to GitHub for runner callbacks. | required |
| `SMITH_CACHE_TOKEN_TTL` | Seconds before cache tokens expire. | `3600` |
| `SMITH_CACHE_SHARED_SECRET` | HMAC secret for cache token minting. | required |
| `SMITH_AGENT_TOKEN_SECRET` | Secret used to mint/verify agent bearer tokens. | required |

### Host Agent (`smith.host_agent`)

| Variable | Description | Default |
| --- | --- | --- |
| `SMITH_AGENT_ID` | Unique identifier for the host agent instance. | required |
| `SMITH_CONTROL_PLANE_URL` | Base URL of the control plane API. | required |
| `SMITH_CONTROL_PLANE_TOKEN` | Bearer token issued by the control plane. | required |
| `SMITH_AGENT_REDIS_URL` | Optional Redis URL for local coordination/caching. | optional |
| `SMITH_CACHE_PROXY_URL` | Cache proxy base URL for artifact downloads. | optional |
| `SMITH_CACHE_TOKEN_SECRET` | Fallback cache token verification secret (lab/dev). | optional |
| `SMITH_CACHE_TOKEN_VALUE` | Pre-minted cache token when bypassing control plane. | optional |
| `SMITH_LOG_SINK_URL` | Logging pipeline ingest endpoint. | optional |
| `SMITH_AGENT_METRICS_HOST` | Prometheus metrics listener host. | `0.0.0.0` |
| `SMITH_AGENT_METRICS_PORT` | Prometheus metrics listener port. | `9460` |
| `SMITH_FC_BIN` | Path to the Firecracker binary. | `/usr/local/bin/firecracker` |
| `SMITH_KERNEL_IMAGE` | Path to kernel image used for VMs. | required |
| `SMITH_ROOTFS_IMAGE` | Root filesystem image path. | required |
| `SMITH_TAP_PREFIX` | Prefix for tap interfaces created per VM. | `smith` |
| `SMITH_JOB_TIMEOUT` | Maximum job runtime in seconds. | `3600` |
| `SMITH_VM_SHUTDOWN_GRACE` | Graceful shutdown wait in seconds. | `30` |
| `SMITH_AGENT_LEASE_RETRIES` | Number of retries for lease requests. | `3` |
| `SMITH_AGENT_LEASE_RETRY_BASE` | Base backoff delay (seconds). | `1.0` |
| `SMITH_AGENT_LEASE_RETRY_MAX` | Maximum backoff delay (seconds). | `15.0` |

### Cache Proxy (`smith.cache_proxy`)

| Variable | Description | Default |
| --- | --- | --- |
| `SMITH_CACHE_STORAGE_PATH` | Filesystem directory for cached artifacts. | `./cache` |
| `SMITH_CACHE_SHARED_SECRET` | HMAC secret for API token validation. | required |
| `SMITH_CACHE_S3_ENDPOINT` | S3-compatible endpoint URL (enable remote backend). | optional |
| `SMITH_CACHE_S3_BUCKET` | S3 bucket/key prefix for remote storage. | optional |
| `SMITH_CACHE_S3_REGION` | AWS region for the S3 endpoint. | optional |
| `SMITH_CACHE_METRICS_DB` | SQLite database used for cache metrics. | `./cache/cache_metrics.db` |
| `SMITH_CACHE_S3_MAX_RETRIES` | Retry attempts for S3 operations. | `3` |
| `SMITH_CACHE_S3_RETRY_BASE` | Base backoff (seconds) for retries. | `0.2` |
| `SMITH_CACHE_S3_RETRY_MAX` | Maximum backoff (seconds). | `2.0` |
| `SMITH_CACHE_S3_CIRCUIT_FAILURES` | Failures before circuit opens. | `5` |
| `SMITH_CACHE_S3_CIRCUIT_RESET` | Seconds before retrying after circuit opens. | `30` |

### Logging Pipeline (`smith.logging_pipeline`)

| Variable | Description | Default |
| --- | --- | --- |
| `SMITH_CLICKHOUSE_URL` | ClickHouse HTTP endpoint (e.g. `http://localhost:8123`). | required |
| `SMITH_CLICKHOUSE_DATABASE` | Target database name. | `smith` |
| `SMITH_CLICKHOUSE_TABLE` | Target table for log ingestion. | `ci_logs` |
| `SMITH_CLICKHOUSE_USERNAME` | Basic auth username for ClickHouse. | optional |
| `SMITH_CLICKHOUSE_PASSWORD` | Basic auth password for ClickHouse. | optional |
| `SMITH_CLICKHOUSE_TIMEOUT` | HTTP timeout in seconds for ClickHouse operations. | `10` |

### Shared observability variables

All services honor the following optional environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `SMITH_LOG_LEVEL` | Structured logging level (`DEBUG`, `INFO`, etc.). | `INFO` |
| `SMITH_OTEL_EXPORTER_ENDPOINT` | OTLP collector endpoint (HTTP or gRPC). | console exporter |
| `SMITH_OTEL_EXPORTER_HEADERS` | Comma-separated OTLP headers (`key=value`). | none |
| `SMITH_OTEL_SAMPLER_RATIO` | Sampling ratio (0.0–1.0) for tracing. | `0.1` |

### Cache proxy backends

- Local filesystem (default): set `SMITH_CACHE_STORAGE_PATH` to a writable directory.
- S3-compatible storage: configure `SMITH_CACHE_S3_ENDPOINT`, `SMITH_CACHE_S3_BUCKET`, optionally `SMITH_CACHE_S3_REGION`, and provide credentials via standard AWS environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
- Resilience tuning: adjust `SMITH_CACHE_S3_MAX_RETRIES`, `SMITH_CACHE_S3_RETRY_BASE`, `SMITH_CACHE_S3_RETRY_MAX`, `SMITH_CACHE_S3_CIRCUIT_FAILURES`, and `SMITH_CACHE_S3_CIRCUIT_RESET` to control exponential backoff and circuit breaker cooldowns for S3 interactions.

## Firecracker Assets
Use the helper script to download Firecracker kernel and root filesystem images:
```bash
python scripts/setup_firecracker_assets.py ./artifacts
```

### Rootfs build pipeline

1. Create a YAML configuration that describes your rootfs versions (example `rootfs.yaml`):
   ```yaml
   rootfs:
     output_dir: ./artifacts/rootfs
     default_version: dev
     versions:
       - name: dev
         base_url: https://example.com/rootfs-dev.ext4
         overlay_dir: ./rootfs_overlays/dev
       - name: ci
         base_path: ./prebuilt/rootfs-ci.ext4
         description: CI ready image
   ```
2. Build all configured versions (downloads, verifies, and stages overlays):
   ```bash
   uv run python -m smith.rootfs.cli build --config rootfs.yaml
   ```
3. Switch the active rootfs version when rolling out updates:
   ```bash
   uv run python -m smith.rootfs.cli activate --config rootfs.yaml ci
   ```

## Reporting CLI

Use the reporting CLI to generate quick snapshots across services:

- Jobs summary:
  ```bash
  python -m smith.cli.report jobs --base-url http://localhost:8000 --token $SMITH_JWT_SECRET
  ```
- Cache usage overview:
  ```bash
  python -m smith.cli.report cache --cache-url http://localhost:8001
  ```
- Log ingestion summary for a specific job:
  ```bash
  python -m smith.cli.report logs --logs-url http://localhost:8002 --job-id 12345 --limit 50
  ```
- Full overview combining jobs, cache, and logs:
  ```bash
  python -m smith.cli.report overview \
    --base-url http://localhost:8000 --token $SMITH_JWT_SECRET \
    --cache-url http://localhost:8001 \
    --logs-url http://localhost:8002
  ```

## Observability

- Structured logging is enabled across services via `structlog`; adjust verbosity with `SMITH_LOG_LEVEL` (e.g. `DEBUG`, `INFO`).
- Enable OpenTelemetry tracing by setting `SMITH_OTEL_EXPORTER_ENDPOINT` (OTLP HTTP/GRPC), optional `SMITH_OTEL_EXPORTER_HEADERS` (`key=value` pairs), and `SMITH_OTEL_SAMPLER_RATIO` (0.0–1.0) to control sampling.

## Deployment Recipes

### Local development stack

1. Export the required environment variables for each service (see [Environment Variables](#environment-variables)).
2. Start the core APIs with uv:
   ```bash
   uv run uvicorn smith.control_plane.main:app --host 0.0.0.0 --port 8000 --reload
   uv run uvicorn smith.cache_proxy.main:app --host 0.0.0.0 --port 8001 --reload
   uv run uvicorn smith.logging_pipeline.main:app --host 0.0.0.0 --port 8002 --reload
   ```
3. Launch a host agent once kernel/rootfs assets are in place:
   ```bash
   uv run python -m smith.host_agent.main
   ```

### Remote host agent

- Install the same wheel (`uv pip install .`) or copy the project to the host.
- Provision kernel/rootfs images with `scripts/setup_firecracker_assets.py`.
- Export `SMITH_CONTROL_PLANE_URL`, `SMITH_CONTROL_PLANE_TOKEN`, and networking variables appropriate for the host.
- Run `python -m smith.host_agent.main` under a process manager (e.g. `systemd` or `supervisord`).

### Minimal cache proxy deployment

```bash
export SMITH_CACHE_SHARED_SECRET="super-secret"
uv run uvicorn smith.cache_proxy.main:app --host 0.0.0.0 --port 8001
```

Configure S3-specific variables when delegating storage to a remote backend.

## Roadmap
- Implement multi-tenant cache usage metrics and eviction policies.
- Support configurable Firecracker rootfs build pipelines and image updates.
- Expose Prometheus metrics for control plane, cache proxy, and host agents.
- Add automated integration tests that exercise cache, logging, and Firecracker workflows end-to-end.

Smith is a work in progress; contributions and suggestions are welcome.
