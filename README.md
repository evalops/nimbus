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
- **Multi-Executor Host Agent**: Polls for assignments, provisions execution environments (Firecracker microVMs, Docker containers, GPU workloads), enforces capability restrictions, and manages warm pools for performance.
- **Executor System**: Pluggable backends supporting Firecracker (secure isolation), Docker (fast startup), and GPU (CUDA workloads) with capability-based job matching.
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

Workflows can target Nimbus runners using capability-based labels:

```yaml
# Secure isolation (default)
runs-on: [nimbus]  # Uses Firecracker microVMs

# Fast startup for CI/CD
runs-on: [nimbus, docker]  # ~200ms startup

# GPU acceleration for ML/AI
runs-on: [nimbus, gpu, pytorch, gpu-count:2]  # 2 GPUs

# Custom configurations
runs-on: [nimbus, docker, image:node:18-alpine]
```

The control plane verifies `workflow_job` signatures, enforces per-org rate limits, and dispatches jobs to agents based on capability matching.

## Pre-built Runners

Nimbus publishes curated container images, such as `nimbus/ai-eval-runner` (Node.js, `eval2otel`, `ollama` client) for evaluation workloads. See [Getting Started](docs/getting-started.md#pre-built-job-runners) for example usage.

## Operations & Hardening

- Day-two procedures, monitoring, and ClickHouse schema live in the [Operations Guide](docs/operations.md).
- Firecracker jailer, seccomp, and capability dropping guidance is documented in [Firecracker Security Hardening](docs/FIRECRACKER_SECURITY.md).

## Roadmap Snapshot

- **Complete**: Multi-tenant isolation, lease fencing, webhook replay protection, distributed rate limiting, metrics endpoint authentication, tenant analytics dashboard, **multi-executor system with Firecracker/Docker/GPU support, warm pools, snapshot boot, comprehensive performance monitoring**.
- **In Progress**: Enhanced GPU scheduling, ARM64 support, advanced resource optimization.
- **Planned**: Kubernetes executor, Windows containers, auto-scaling warm pools, cost optimization features.

## Contributing

Nimbus is ready for production deployments with a mature multi-executor architecture. See the [Executor System Guide](docs/EXECUTOR_SYSTEM.md) for comprehensive usage documentation. Contributions welcome in:
- New executor implementations (Kubernetes, ARM64, Windows)
- Advanced GPU scheduling and optimization
- Performance analysis and cost optimization
- Extended warm pool strategies
