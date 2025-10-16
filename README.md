# Nimbus

Nimbus is a self-hosted CI platform built around Firecracker microVMs, org-scoped storage, and end-to-end observability for AI evaluation workloads. It replaces GitHub-hosted runners while keeping execution on infrastructure you control.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration Reference](docs/configuration.md)
- [Operations Guide](docs/operations.md)
- [Firecracker Security Hardening](docs/FIRECRACKER_SECURITY.md)
- [ClickHouse Schema](docs/CLICKHOUSE_SCHEMA.md)
- [Runbook](docs/runbook.md)

## Architecture Overview

- **Control Plane**: Handles GitHub webhooks (HMAC + timestamp validation), manages DB-backed job leases and rate limits, and coordinates agent registration.
- **Host Agent**: Polls for assignments, provisions Firecracker microVMs, enforces capability restrictions, and persists in-flight state.
- **Cache Proxy**: Org-scoped artifact cache with optional S3 backend, eviction policies, and protected metrics endpoint.
- **Logging Pipeline**: Authenticated ClickHouse ingestion with org/repo filters on queries.
- **Docker Layer Cache**: OCI-compatible registry that enforces org-prefixed repositories and metadata ownership.
- **Web Dashboard**: React/Vite SPA for monitoring jobs, agents, logs, and system health.

### Security Highlights

- Lease fencing with fence tokens prevents duplicate job execution.
- Delivery ID tracking plus timestamp tolerance block webhook replays.
- Org-level access controls across cache, logging, and Docker registry assets.
- Metrics endpoints require a bearer token or loopback access by default.

## Quick Start

1. Install dependencies and bootstrap the environment (`uv venv`, `uv pip install -e .`).
2. Configure the required environment variables and secrets (see [Configuration](docs/configuration.md)).
3. Follow the detailed setup in [Getting Started](docs/getting-started.md) to launch services and run the test suite.

## GitHub Actions Integration

Workflows can target Nimbus runners by setting `runs-on: nimbus`. The control plane verifies `workflow_job` signatures (`X-Hub-Signature-256` plus `X-Hub-Signature-Timestamp`), enforces per-org rate limits, and dispatches jobs to agents via leased assignments.

## Pre-built Runners

Nimbus publishes curated container images, such as `nimbus/ai-eval-runner` (Node.js, `eval2otel`, `ollama` client) for evaluation workloads. See [Getting Started](docs/getting-started.md#pre-built-job-runners) for example usage.

## Operations & Hardening

- Day-two procedures, monitoring, and ClickHouse schema live in the [Operations Guide](docs/operations.md).
- Firecracker jailer, seccomp, and capability dropping guidance is documented in [Firecracker Security Hardening](docs/FIRECRACKER_SECURITY.md).

## Roadmap Snapshot

- **Complete**: Multi-tenant isolation, lease fencing, webhook replay protection, distributed rate limiting, metrics endpoint authentication.
- **In Progress**: Schema migrations, expanded integration tests, jailer rollout.
- **Planned**: Storage quotas, rootfs attestation, performance tuning, snapshot boot support.

## Contributing

Nimbus is ready for pilot deployments; active readiness tracking lives in [docs/PRE_PILOT_READINESS.md](docs/PRE_PILOT_READINESS.md). Contributions improving security, observability, and distributed test coverage are welcome.
- Performance optimization
- Additional eval-specific runners
