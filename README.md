# Nimbus

Nimbus is a self-hosted CI platform built around Firecracker microVMs, org-scoped storage, and end-to-end observability for AI evaluation workloads. It replaces GitHub-hosted runners while keeping execution on infrastructure you control.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration Reference](docs/configuration.md)
- [Operations Guide](docs/operations.md)
- [Onboarding Playbook](docs/onboarding.md)
- [GitHub Actions Migration Guide](docs/github-actions-migration.md)
- [ROI Calculator](docs/roi-calculator.md)
- [Firecracker Security Hardening](docs/FIRECRACKER_SECURITY.md)
- [ClickHouse Schema](docs/CLICKHOUSE_SCHEMA.md)
- [Runbook](docs/runbook.md)
- [Policy-as-Code](docs/policy-as-code.md)

## Architecture Overview

- **Control Plane (`src/nimbus/control_plane`)**: Validates GitHub `workflow_job` webhooks (HMAC, timestamp, delivery replay fence), enforces distributed per-org rate limits, issues agent/cache tokens, and brokers job leases over Redis + Postgres. It also exposes SAML SSO, SCIM provisioning, service accounts, and compliance export logging.
- **Host Agent (`src/nimbus/host_agent`)**: Runs Firecracker microVMs with snapshot boot and network fencing, plus Docker and GPU executors selected by capability labels. The agent layers in warm pools, resource/performance telemetry, offline egress enforcement, SBOM generation, and supply-chain allow/deny policies.
- **Executor System (`src/nimbus/runners`)**: Pluggable executors share a common `Executor` protocol, pool manager, resource tracker, and watchdogs for timeouts and lease renewal fencing.
- **Cache Proxy (`src/nimbus/cache_proxy`)**: Multi-tenant cache front-end with S3/local backends, org quotas, eviction metrics, and circuit-breakers to isolate backend failures.
- **Docker Layer Cache (`src/nimbus/docker_cache`)**: Minimal OCI registry enforcing org-prefixed repositories, blob accounting, and scoped cache tokens for push/pull.
- **Logging Pipeline (`src/nimbus/logging_pipeline`)**: ClickHouse-backed ingestion API with batched writes, scoped query filters, and hardened metrics endpoints.
- **Web Dashboard (`web`)**: React/Vite SPA that surfaces job queues, agent health, logs, and compliance metadata via the public API.

### Security Highlights

- Lease fencing with rotating fence tokens prevents duplicate job execution across agents.
- Webhook signature + timestamp validation with replay tracking (`x-github-delivery`) blocks tampering and replays.
- Agent/cache/service-account tokens are org scoped, versioned, and auditable through Postgres-backed ledgers.
- Offline-mode egress enforcement combines metadata endpoint deny-lists, regex policy packs, and explicit registry allow-lists.
- Rootfs attestation, cosign provenance checks, and per-job SBOM generation tighten host supply-chain posture.
- Metrics and admin endpoints require bearer tokens and can be IP-filtered for additional hardening.

## Quick Start

1. Install dependencies and bootstrap the environment (`uv venv`, `uv pip install -e .`).
2. Configure the required environment variables and secrets (see [Configuration](docs/configuration.md)).
3. Follow the detailed setup in [Getting Started](docs/getting-started.md) to launch services and supporting infrastructure.
4. Run the automated checks with `uv run pytest` to validate control plane, host agent, caching, and executor integrations.

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

## Repository Layout

- `src/nimbus/control_plane`: FastAPI application, database models, RBAC/SCIM/SAML integrations, compliance tooling.
- `src/nimbus/host_agent`: Firecracker launcher, multi-executor orchestration, warm pools, egress enforcement, and SSH utilities.
- `src/nimbus/runners`: Executor implementations (Firecracker, Docker, GPU), pool manager, resource tracker, performance monitor.
- `src/nimbus/cache_proxy` & `src/nimbus/docker_cache`: Artifact/cache services with metrics, quota enforcement, and S3/OCI backends.
- `src/nimbus/logging_pipeline`: ClickHouse ingestion and querying service for job logs.
- `web`: Vite/React dashboard for operational monitoring.
- `tests`: Extensive pytest suite covering services, executors, security controls, and CLI tooling.

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
