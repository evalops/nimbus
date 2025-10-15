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

## Roadmap
- Implement multi-tenant cache usage metrics and eviction policies.
- Support configurable Firecracker rootfs build pipelines and image updates.
- Expose Prometheus metrics for control plane, cache proxy, and host agents.
- Add automated integration tests that exercise cache, logging, and Firecracker workflows end-to-end.

Smith is a work in progress; contributions and suggestions are welcome.
