# Nimbus

Nimbus is a self-hosted CI platform designed around Firecracker microVMs, org-scoped storage, and built-in observability for AI evaluation pipelines. It can replace GitHub-hosted runners while keeping workloads on infrastructure you control.

## Key Capabilities

- Self-managed runners using Firecracker microVMs with lease fencing and crash recovery
- Multi-tenant isolation for cache artifacts, Docker layers, and log ingestion
- GitHub webhook integration with signature verification, replay protection, and per-org rate limits
- Structured logging and optional OpenTelemetry export for end-to-end tracing
- Optional S3 cache backend and ClickHouse-compatible logging pipeline

> **Acknowledgement:** Nimbus builds on key ideas from [Blacksmith.sh](https://blacksmith.sh). Their documentation on architecture, security posture, and operational trade-offs heavily influenced this implementation.

## Components

- **Control Plane (FastAPI):** Receives GitHub webhooks with signature verification and replay protection, manages job leases with fence tokens, enforces per-org rate limits, and coordinates runner registration.
- **Host Agent:** Polls for work with lease renewal heartbeats, manages Firecracker microVMs with automatic cleanup on crash, and persists active job state in Postgres.
- **Cache Proxy:** Org-scoped artifact cache with pull/push permissions, backed by filesystem or S3-compatible storage with circuit breaker resilience and Postgres-backed metrics.
- **Logging Pipeline:** Authenticated log ingestion to ClickHouse with org/repo boundaries enforced on all queries.
- **Docker Layer Cache Registry:** OCI-compatible registry with org-prefixed repositories and blob ownership validation backed by Postgres metadata.
- **Web Dashboard:** React + Vite SPA for monitoring jobs, agents, logs, and system health.
- **Optional SSH/DNS Helpers:** Secure SSH access to running VMs with port allocation and automatic session expiry.

### Security Features

- **Lease Fencing**: DB-backed leases with fence tokens prevent double-claiming during network partitions
- **Multi-Tenant Isolation**: Org-scoped access controls on cache, logs, and Docker registry
- **Secret Masking**: All sensitive configuration automatically redacted in logs and errors
- **Webhook Protection**: Delivery ID tracking prevents replay attacks
- **Rate Limiting**: Per-org job submission limits to prevent abuse
- **Idempotent Cleanup**: Automatic reaper on startup handles orphaned resources from crashes

## Pre-built Job Runners

Nimbus provides container images for common use cases. These images can be used directly in job submissions without needing to build your own.

### AI Evaluation Runner (`nimbus/ai-eval-runner`)

A container for running AI model evaluations with built-in observability.

- **Contents:** Node.js 20, `eval2otel`, and the `ollama` client.
- **Purpose:** Use this runner to execute evaluation scripts that call an AI model, process the results with `eval2otel`, and automatically export traces and metrics to the OpenTelemetry endpoint configured in your Nimbus environment.

**Example Usage:**

To use this runner, reference the `nimbus/ai-eval-runner` image when submitting a job. Your job's command would be the Node.js script to execute.

A hypothetical job submission might look like this:

```bash
nimbus-cli jobs submit \
  --image nimbus/ai-eval-runner:latest \
  --cmd "node /path/to/your/eval_script.js" \
  --env OTEL_SERVICE_NAME=my-text-generation-eval \
  --env NIMBUS_OTEL_EXPORTER_ENDPOINT=http://your-otel-collector:4317 \
  --env OLLAMA_HOST=http://your-ollama-host:11434 \
  --env MODEL=gemma:2b \
  --env PROMPT="What is the airspeed velocity of an unladen swallow?"
```

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
1. Receive and verify the `workflow_job` webhook from GitHub (signature + replay protection)
2. Check per-org rate limits and generate a one-time runner registration token via the GitHub API
3. Enqueue the job assignment to Redis with org-scoped cache token
4. Agent leases the job with DB-backed fence token and starts heartbeat renewal
5. Firecracker microVM spins up, registers as a GitHub Actions runner, and executes your workflow
6. Job completion releases the lease; automatic reaper handles any orphaned resources

Jobs without the `nimbus` label are ignored by the control plane, allowing you to mix Nimbus runners with GitHub-hosted runners in the same repository.

## Getting Started
1. Install dependencies with [uv](https://github.com/astral-sh/uv):
   ```bash
   uv venv .venv
   uv pip install -e .
   ```
2. Provision PostgreSQL databases (or schemas) for the control plane, host agent state, cache metrics, and Docker metadata. Example DSNs:
   ```
   export NIMBUS_DATABASE_URL="postgresql+asyncpg://<user>:<password>@db/nimbus_control"
   export NIMBUS_AGENT_STATE_DATABASE_URL="postgresql+asyncpg://<user>:<password>@db/nimbus_agent_state"
   export NIMBUS_CACHE_METRICS_DB="postgresql+psycopg://<user>:<password>@db/nimbus_cache_metrics"
   export NIMBUS_DOCKER_CACHE_DB_PATH="postgresql+psycopg://<user>:<password>@db/nimbus_docker_cache"
   ```
3. Define the remaining environment variables for the control plane, host agent, cache proxy, and logging pipeline (see [Environment Variables](#environment-variables) for required keys such as `NIMBUS_GITHUB_WEBHOOK_SECRET`, `NIMBUS_AGENT_TOKEN_SECRET`, and `NIMBUS_CACHE_SHARED_SECRET`).
4. Launch services with uvicorn (example):
   ```bash
   uvicorn nimbus.control_plane.main:app --reload
   uvicorn nimbus.cache_proxy.main:app --reload --port 8001
   uvicorn nimbus.logging_pipeline.main:app --reload --port 8002
   python -m nimbus.host_agent.main
   ```
5. Run the unit and integration test suite:
    ```bash
    uv run pytest
    ```

### Useful CLI commands

```bash
# Recent jobs
python -m nimbus.cli.jobs recent --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --limit 10

# Queue health
python -m nimbus.cli.jobs status --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET

# Logs for a job
python -m nimbus.cli.logs --logs-url http://localhost:8002 --job-id 12345 --limit 50

# Mint cache token
python -m nimbus.cli.cache --secret $NIMBUS_CACHE_SHARED_SECRET --org-id 123 --ttl 3600

# Mint agent token
python -m nimbus.cli.auth --agent-id agent-001 --secret $NIMBUS_AGENT_TOKEN_SECRET --ttl 3600
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
| `NIMBUS_DATABASE_URL` | Async SQLAlchemy database URL (e.g. `postgresql+asyncpg://user:pass@host/nimbus_control`). | required |
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
| `NIMBUS_AGENT_STATE_DATABASE_URL` | Async SQLAlchemy URL for host agent state store. | `postgresql+asyncpg://localhost/nimbus_agent_state` |
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
| `NIMBUS_CACHE_METRICS_DB` | SQLAlchemy database URL for cache metrics (Postgres recommended). | `postgresql+psycopg://localhost/nimbus_cache_metrics` |
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
| `NIMBUS_DOCKER_CACHE_DB_PATH` | SQLAlchemy database URL for Docker cache metadata (Postgres recommended). | `postgresql+psycopg://localhost/nimbus_docker_cache` |
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

### Download Kernel and Rootfs

Use the helper script to download Firecracker kernel and root filesystem images:
```bash
python scripts/setup_firecracker_assets.py ./artifacts
```

### Security Setup (Production)

Install jailer, seccomp profiles, and capability dropping:

```bash
# 1. Download architecture-specific seccomp profile
python scripts/setup_seccomp_profile.py /etc/nimbus

# 2. Install security components (creates nimbus user, sets up directories)
sudo bash scripts/install-security.sh

# 3. Configure agent to use jailer
cat >> .env << EOF
NIMBUS_JAILER_BIN=/usr/local/bin/jailer
NIMBUS_SECCOMP_FILTER=/etc/nimbus/seccomp-$(uname -m).json
NIMBUS_JAILER_UID=$(id -u nimbus)
NIMBUS_JAILER_GID=$(id -g nimbus)
NIMBUS_JAILER_CHROOT_BASE=/srv/jailer
EOF

# 4. Start agent with privileged setup (drops to CAP_NET_ADMIN only)
sudo /usr/local/bin/nimbus-privileged-setup.sh python -m nimbus.host_agent.main
```

**Security features enabled:**
- Firecracker runs in chroot jail
- Process drops to non-root user (UID 1000)
- PID namespace isolation (--new-pid-ns)
- Architecture-specific seccomp filtering
- CAP_NET_ADMIN only (no CAP_SYS_ADMIN)

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

## Production Deployment

### Pre-Pilot Checklist

Before deploying to production, review [docs/PRE_PILOT_GAPS.md](docs/PRE_PILOT_GAPS.md) for the complete security and reliability assessment.

**Critical items (all implemented):**
- Lease fencing with fence tokens and heartbeat renewal
- Idempotent teardown and startup reaper for crash recovery
- Multi-tenant isolation (cache, logs, Docker registry)
- Secret masking with Pydantic SecretStr
- Webhook replay protection via delivery ID tracking
- Per-org rate limiting on job submissions
- SSH port allocation with unique constraints

**Recommended for scale:**
- Alembic migrations (currently using ensure_schema)
- Comprehensive integration test suite
- Health check endpoints (/healthz) for K8s readiness probes

### Multi-Tenant Configuration

All services enforce org-level isolation. Key configuration:

```bash
# Shared secret for cache tokens (used across all services)
NIMBUS_CACHE_SHARED_SECRET="your-secure-secret-here"

# Job lease TTL (default: 300s)
NIMBUS_JOB_LEASE_TTL=300

# Per-org rate limits (default: 100 jobs/minute)
NIMBUS_ORG_JOB_RATE_LIMIT=100
NIMBUS_ORG_RATE_INTERVAL=60
```

**Important**: Cache tokens are scoped with `pull:org-{id}` and `push:org-{id}` permissions. Docker repository names **must** be prefixed with `org-{id}/` to enforce boundaries.

### Security Hardening

See [docs/FIRECRACKER_SECURITY.md](docs/FIRECRACKER_SECURITY.md) for Firecracker jailer and seccomp configuration.

Recommended additional hardening:
- Run Firecracker under jailer with seccomp profile
- Drop unnecessary capabilities from host agent process
- Use network namespaces per VM for isolation
- Enable HTTPS at ingress with trusted proxy headers
- Bind metrics endpoints to localhost or private network

### Monitoring

Key metrics to monitor in production:
- `nimbus_control_plane_webhook_replays_blocked` - Replay attack attempts
- `nimbus_control_plane_org_rate_limits_hit` - Organizations hitting limits
- `nimbus_host_agent_job_timeouts_total` - Jobs timing out
- `nimbus_host_agent_lease_errors_total` - Lease acquisition failures
- `nimbus_cache_evictions_total` - Cache pressure

Prometheus scrape endpoints:
- Control plane: `http://localhost:8000/metrics`
- Host agent: `http://localhost:9460/metrics`
- Cache proxy: `http://localhost:8001/metrics`

### ClickHouse Schema

The logging pipeline requires a specific ClickHouse schema. See [docs/CLICKHOUSE_SCHEMA.md](docs/CLICKHOUSE_SCHEMA.md) for the complete DDL and multi-tenant isolation setup.

**Quick setup:**
```sql
CREATE TABLE IF NOT EXISTS nimbus.ci_logs (
    job_id UInt64,
    agent_id String,
    org_id Nullable(UInt64),
    repo_id Nullable(UInt64),
    level String,
    message String,
    ts DateTime64(3),
    inserted_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (org_id, repo_id, job_id, ts)
PARTITION BY toYYYYMM(ts);
```

## Roadmap

**Completed:**
- Multi-tenant isolation with org-scoped access controls
- Lease fencing to prevent job double-claiming
- Webhook replay protection
- Distributed per-org rate limiting
- Idempotent cleanup and crash recovery
- Secret masking and secure credential handling
- Proxy header trust validation
- S3 error handling and circuit breakers
- Metrics endpoint security (localhost-only default)

**In Progress:**
- Alembic migrations for schema versioning
- Comprehensive integration test suite
- Firecracker jailer and seccomp integration

**Planned:**
- Per-org storage quotas and usage metrics
- Rootfs content addressing and attestation
- Performance knobs (vCPU pinning, cgroup tuning)
- Advanced eval observability (token usage, quality scores)
- Snapshot-based VM boot for faster startup

## Contributing

Nimbus is production-ready for pilot deployments. See [docs/SELF_REVIEW.md](docs/SELF_REVIEW.md) for current status and [docs/PRE_PILOT_GAPS.md](docs/PRE_PILOT_GAPS.md) for completed security work.

Contributions welcome! Key areas:
- Integration test coverage
- Distributed systems testing
- Performance optimization
- Additional eval-specific runners
