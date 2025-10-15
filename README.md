# Nimbus

Nimbus is an experimental platform that mirrors key ideas from [Blacksmith.sh](https://blacksmith.sh): an AWS-hosted control plane that orchestrates GitHub Actions jobs onto bare-metal hosts running Firecracker microVMs. This repository contains a prototype implementation that can be used as a learning tool or homelab foundation while crediting the original Blacksmith team for the inspiration.

> **Acknowledgement:** Nimbus exists thanks to the engineering leadership and public write-ups from the [Blacksmith](https://blacksmith.sh) team. Their transparency around architecture, security posture, and operational trade-offs set the blueprint for this prototype. If you are looking for a production-ready solution—or want to support the folks who pioneered these ideas—please start with Blacksmith.

## Components
- **Control Plane (FastAPI):** Receives GitHub webhooks (with signature verification), issues runner registration tokens, and queues jobs in Redis.
- **Host Agent:** Polls the control plane for work, manages Firecracker microVMs, and forwards Firecracker logs to the logging pipeline when configured.
- Ensure host agents have permissions to create tap devices and bridges (requires `ip`/`iproute2`).
- **Cache Proxy:** Provides a simple artifact cache API backed by the filesystem or an S3-compatible endpoint (MinIO/Ceph) with HMAC-signed tokens.
- **Logging Pipeline:** Streams job logs into ClickHouse using JSONEachRow inserts.
- **Optional SSH/DNS Helpers:** Command snippets for exposing live SSH sessions and registering VM hostnames.
- **Docker Layer Cache Registry:** Implements a minimal OCI-compatible blob/manifest store to accelerate container builds.
- **Web Dashboard:** React + Vite single-page app for monitoring jobs, agents, logs, and configuration status.

## Using Nimbus with GitHub Actions

Once your Nimbus infrastructure is configured and running, you can use it to execute GitHub Actions workflows by specifying `runs-on: nimbus` in your workflow files:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: nimbus
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: |
          echo "Running on Nimbus!"
          # Your test commands here
```

The control plane will:
1. Receive the `workflow_job` webhook from GitHub when jobs with the `nimbus` label are queued
2. Generate a one-time runner registration token via the GitHub API
3. Enqueue the job assignment to Redis
4. Wait for a host agent to lease the job
5. The host agent spins up a Firecracker microVM that registers as a GitHub Actions runner and executes your workflow

Jobs without the `nimbus` label are ignored by the control plane, allowing you to mix Nimbus runners with GitHub-hosted runners in the same repository.

## Getting Started
1. Install dependencies with [uv](https://github.com/astral-sh/uv):
   ```bash
   uv venv .venv
   uv pip install -e .
   ```
2. Define environment variables for the control plane, host agent, cache proxy, and logging pipeline services (see inline comments in the settings classes for required keys, including `NIMBUS_GITHUB_WEBHOOK_SECRET`, `NIMBUS_AGENT_TOKEN_SECRET`, and `NIMBUS_CACHE_SHARED_SECRET`).
3. Launch services with uvicorn (example):
   ```bash
   uvicorn nimbus.control_plane.main:app --reload
   uvicorn nimbus.cache_proxy.main:app --reload --port 8001
   uvicorn nimbus.logging_pipeline.main:app --reload --port 8002
   python -m nimbus.host_agent.main
   ```
4. Optionally provide a fallback cache token to hosts via `NIMBUS_CACHE_TOKEN_SECRET` and `NIMBUS_CACHE_TOKEN_VALUE` when experimenting without live control-plane minted tokens.
5. Inspect recent jobs from the command line (example):
   ```bash
   python -m nimbus.cli.jobs recent --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --limit 10
   ```
6. Check overall queue health:
   ```bash
   python -m nimbus.cli.jobs status --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET
   ```
7. Query logs for a job:
   ```bash
   python -m nimbus.cli.logs --logs-url http://localhost:8002 --job-id 12345 --limit 50
   ```
8. Mint a cache token for testing:
   ```bash
   python -m nimbus.cli.cache --secret $NIMBUS_CACHE_SHARED_SECRET --org-id 123 --ttl 3600
   ```
9. Mint an agent token for a host:
   ```bash
   python -m nimbus.cli.auth --agent-id agent-001 --secret $NIMBUS_AGENT_TOKEN_SECRET --ttl 3600
   ```
10. Run the unit and integration test suite:
    ```bash
    uv run pytest
    ```

## Environment Variables

### Control Plane (`nimbus.control_plane`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_GITHUB_APP_ID` | GitHub App numeric identifier. | required |
| `NIMBUS_GITHUB_APP_PRIVATE_KEY` | PEM-encoded private key for the GitHub App. | required |
| `NIMBUS_GITHUB_APP_INSTALLATION_ID` | Installation ID for the GitHub App. | required |
| `NIMBUS_GITHUB_WEBHOOK_SECRET` | Shared secret for validating webhook signatures. | required |
| `NIMBUS_REDIS_URL` | Redis connection string (e.g. `redis://localhost:6379/0`). | required |
| `NIMBUS_DATABASE_URL` | SQLAlchemy async database URL (e.g. `sqlite+aiosqlite:///./nimbus.db`). | required |
| `NIMBUS_JWT_SECRET` | Secret used to mint control-plane JWTs for CLI access. | required |
| `NIMBUS_PUBLIC_BASE_URL` | Public URL base returned to GitHub for runner callbacks. | required |
| `NIMBUS_CACHE_TOKEN_TTL` | Seconds before cache tokens expire. | `3600` |
| `NIMBUS_CACHE_SHARED_SECRET` | HMAC secret for cache token minting. | required |
| `NIMBUS_AGENT_TOKEN_SECRET` | Secret used to mint/verify agent bearer tokens. | required |
| `NIMBUS_AGENT_TOKEN_RATE_LIMIT` | Maximum agent token mint operations per interval. | `15` |
| `NIMBUS_AGENT_TOKEN_RATE_INTERVAL` | Interval window (seconds) for token mint rate limiting. | `60` |
| `NIMBUS_ADMIN_ALLOWED_SUBJECTS` | Comma-separated list of allowed admin JWT subjects. | empty (all subjects) |

### Host Agent (`nimbus.host_agent`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_AGENT_ID` | Unique identifier for the host agent instance. | required |
| `NIMBUS_CONTROL_PLANE_URL` | Base URL of the control plane API. | required |
| `NIMBUS_CONTROL_PLANE_TOKEN` | Bearer token issued by the control plane. | required |
| `NIMBUS_AGENT_REDIS_URL` | Optional Redis URL for local coordination/caching. | optional |
| `NIMBUS_CACHE_PROXY_URL` | Cache proxy base URL for artifact downloads. | optional |
| `NIMBUS_CACHE_TOKEN_SECRET` | Fallback cache token verification secret (lab/dev). | optional |
| `NIMBUS_CACHE_TOKEN_VALUE` | Pre-minted cache token when bypassing control plane. | optional |
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

### Cache Proxy (`nimbus.cache_proxy`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_CACHE_STORAGE_PATH` | Filesystem directory for cached artifacts. | `./cache` |
| `NIMBUS_CACHE_SHARED_SECRET` | HMAC secret for API token validation. | required |
| `NIMBUS_CACHE_S3_ENDPOINT` | S3-compatible endpoint URL (enable remote backend). | optional |
| `NIMBUS_CACHE_S3_BUCKET` | S3 bucket/key prefix for remote storage. | optional |
| `NIMBUS_CACHE_S3_REGION` | AWS region for the S3 endpoint. | optional |
| `NIMBUS_CACHE_METRICS_DB` | SQLite database used for cache metrics. | `./cache/cache_metrics.db` |
| `NIMBUS_CACHE_S3_MAX_RETRIES` | Retry attempts for S3 operations. | `3` |
| `NIMBUS_CACHE_S3_RETRY_BASE` | Base backoff (seconds) for retries. | `0.2` |
| `NIMBUS_CACHE_S3_RETRY_MAX` | Maximum backoff (seconds). | `2.0` |
| `NIMBUS_CACHE_S3_CIRCUIT_FAILURES` | Failures before circuit opens. | `5` |
| `NIMBUS_CACHE_S3_CIRCUIT_RESET` | Seconds before retrying after circuit opens. | `30` |
| `NIMBUS_CACHE_MAX_BYTES` | Optional storage cap that triggers eviction of cold entries. | unset |
| `NIMBUS_CACHE_EVICTION_BATCH` | Number of cold entries inspected per eviction pass. | `100` |

### Docker Layer Cache Registry (`nimbus.docker_cache`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_CACHE_SHARED_SECRET` | Shared secret reused for validating cache tokens. | required |
| `NIMBUS_DOCKER_CACHE_STORAGE_PATH` | Root directory for blob content. | `./docker-cache/blobs` |
| `NIMBUS_DOCKER_CACHE_UPLOAD_PATH` | Temporary upload staging directory. | `./docker-cache/uploads` |
| `NIMBUS_DOCKER_CACHE_DB_PATH` | SQLite metadata database path. | `./docker-cache/metadata.db` |
| `NIMBUS_DOCKER_CACHE_MAX_BYTES` | Optional byte limit for on-disk blobs (0 disables). | `0` |

### Web Dashboard (`web/`)

Vite environment variables are prefixed with `VITE_` and can be provided via `.env` in the `web/` directory or compose environment overrides.

| Variable | Description | Default |
| --- | --- | --- |
| `VITE_DEFAULT_CONTROL_PLANE_URL` | Base URL used when settings are blank. | unset (use compose default) |
| `VITE_DEFAULT_LOGGING_URL` | Optional logging endpoint default. | unset |

Dashboard settings are persisted in-memory; tokens are cleared after a browser refresh for safety.

### Logging Pipeline (`nimbus.logging_pipeline`)

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_CLICKHOUSE_URL` | ClickHouse HTTP endpoint (e.g. `http://localhost:8123`). | required |
| `NIMBUS_CLICKHOUSE_DATABASE` | Target database name. | `nimbus` |
| `NIMBUS_CLICKHOUSE_TABLE` | Target table for log ingestion. | `ci_logs` |
| `NIMBUS_CLICKHOUSE_USERNAME` | Basic auth username for ClickHouse. | optional |
| `NIMBUS_CLICKHOUSE_PASSWORD` | Basic auth password for ClickHouse. | optional |
| `NIMBUS_CLICKHOUSE_TIMEOUT` | HTTP timeout in seconds for ClickHouse operations. | `10` |

### Shared observability variables

All services honor the following optional environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `NIMBUS_LOG_LEVEL` | Structured logging level (`DEBUG`, `INFO`, etc.). | `INFO` |
| `NIMBUS_OTEL_EXPORTER_ENDPOINT` | OTLP collector endpoint (HTTP or gRPC). | console exporter |
| `NIMBUS_OTEL_EXPORTER_HEADERS` | Comma-separated OTLP headers (`key=value`). | none |
| `NIMBUS_OTEL_SAMPLER_RATIO` | Sampling ratio (0.0–1.0) for tracing. | `0.1` |

### Bootstrap Utilities

- **Environment generation** – run `uv run python scripts/bootstrap_compose.py --output .env` to create a secrets-filled `.env`. Append `--control-plane-url http://localhost:8000 --admin-token <jwt>` to mint an initial host-agent token, and `--secrets-output bootstrap-tokens.json` to capture minted tokens in a separate JSON file for secure distribution.
- **Manual setup** – alternatively copy `compose.env.sample` and populate the required secrets by hand using the `nimbus.cli.admin` commands described below.

### Developer Shortcuts

- **Makefile targets** – `make bootstrap`, `make compose-up`, `make compose-down`, `make test`, `make build-web`, `make lint-web`, and `make build-docker-cache` wrap common commands (including the frontend and registry).
- **uv scripts** – the same workflows are exposed via `uv run bootstrap`, `uv run compose-up`, and `uv run test` for consistent cross-platform invocation.
- **Compose helper** – call `python scripts/compose_manager.py <command>` (e.g. `up`, `down`, `logs --follow`) for consistent env-file handling and profile selection.

### Docker Compose Stack

1. Ensure `.env` is prepared via the bootstrap script. If you minted an agent token into `bootstrap-tokens.json`, copy `agent_token` into `NIMBUS_CONTROL_PLANE_TOKEN` before starting services.
2. Place Firecracker assets in `./artifacts/`: `vmlinux`, `rootfs.ext4`, and a `firecracker` binary (matching the path specified in `compose.yaml`).
3. Launch the stack with `docker compose up --build control-plane cache-proxy logging-pipeline docker-cache web`. Start the host agent when KVM and Firecracker are available by adding the `agent` profile (`docker compose --profile agent up host-agent`). The web dashboard is available on <http://localhost:5173> and proxies API calls to the compose services.

> **Optional smoke test:** run `NIMBUS_RUN_COMPOSE_TESTS=1 uv run pytest tests/system/test_compose_stack.py` to validate the compose configuration (requires Docker).

### Cache proxy backends

- Local filesystem (default): set `NIMBUS_CACHE_STORAGE_PATH` to a writable directory.
- S3-compatible storage: configure `NIMBUS_CACHE_S3_ENDPOINT`, `NIMBUS_CACHE_S3_BUCKET`, optionally `NIMBUS_CACHE_S3_REGION`, and provide credentials via standard AWS environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
- Resilience tuning: adjust `NIMBUS_CACHE_S3_MAX_RETRIES`, `NIMBUS_CACHE_S3_RETRY_BASE`, `NIMBUS_CACHE_S3_RETRY_MAX`, `NIMBUS_CACHE_S3_CIRCUIT_FAILURES`, and `NIMBUS_CACHE_S3_CIRCUIT_RESET` to control exponential backoff and circuit breaker cooldowns for S3 interactions. Pair `NIMBUS_CACHE_MAX_BYTES` with `NIMBUS_CACHE_EVICTION_BATCH` to cap disk usage and control eviction sweep size.

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
   uv run python -m nimbus.rootfs.cli build --config rootfs.yaml
   ```
3. Switch the active rootfs version when rolling out updates:
   ```bash
   uv run python -m nimbus.rootfs.cli activate --config rootfs.yaml ci
   ```

## Reporting CLI

Use the reporting CLI to generate quick snapshots across services:

- Jobs summary:
  ```bash
  python -m nimbus.cli.report jobs --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET
  ```
- Cache usage overview:
  ```bash
  python -m nimbus.cli.report cache --cache-url http://localhost:8001
  ```
- Log ingestion summary for a specific job:
  ```bash
  python -m nimbus.cli.report logs --logs-url http://localhost:8002 --job-id 12345 --limit 50
  ```
- Full overview combining jobs, cache, and logs:
  ```bash
  python -m nimbus.cli.report overview \
    --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET \
    --cache-url http://localhost:8001 \
    --logs-url http://localhost:8002
  ```

## Observability

- Structured logging is enabled across services via `structlog`; adjust verbosity with `NIMBUS_LOG_LEVEL` (e.g. `DEBUG`, `INFO`).
- Enable OpenTelemetry tracing by setting `NIMBUS_OTEL_EXPORTER_ENDPOINT` (OTLP HTTP/GRPC), optional `NIMBUS_OTEL_EXPORTER_HEADERS` (`key=value` pairs), and `NIMBUS_OTEL_SAMPLER_RATIO` (0.0–1.0) to control sampling.

## Deployment Recipes

### Local development stack

1. Export the required environment variables for each service (see [Environment Variables](#environment-variables)).
2. Start the core APIs with uv:
   ```bash
   uv run uvicorn nimbus.control_plane.main:app --host 0.0.0.0 --port 8000 --reload
   uv run uvicorn nimbus.cache_proxy.main:app --host 0.0.0.0 --port 8001 --reload
   uv run uvicorn nimbus.logging_pipeline.main:app --host 0.0.0.0 --port 8002 --reload
   ```
3. Launch a host agent once kernel/rootfs assets are in place:
   ```bash
   uv run python -m nimbus.host_agent.main
   ```

### Remote host agent

- Install the same wheel (`uv pip install .`) or copy the project to the host.
- Provision kernel/rootfs images with `scripts/setup_firecracker_assets.py`.
- Export `NIMBUS_CONTROL_PLANE_URL`, `NIMBUS_CONTROL_PLANE_TOKEN`, and networking variables appropriate for the host.
- Run `python -m nimbus.host_agent.main` under a process manager (e.g. `systemd` or `supervisord`).

### Minimal cache proxy deployment

```bash
export NIMBUS_CACHE_SHARED_SECRET="super-secret"
uv run uvicorn nimbus.cache_proxy.main:app --host 0.0.0.0 --port 8001
```

Configure S3-specific variables when delegating storage to a remote backend.

## Roadmap
- Implement multi-tenant cache usage metrics and eviction policies.
- Support configurable Firecracker rootfs build pipelines and image updates.
- Expose Prometheus metrics for control plane, cache proxy, and host agents.
- Add automated integration tests that exercise cache, logging, and Firecracker workflows end-to-end.

Nimbus is a work in progress; contributions and suggestions are welcome.
