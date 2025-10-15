# Smith

Smith is an experimental platform that mirrors key ideas from Blacksmith.sh: an AWS-hosted control plane that orchestrates GitHub Actions jobs onto bare-metal hosts running Firecracker microVMs. This repository contains a prototype implementation that can be used as a learning tool or homelab foundation.

## Components
- **Control Plane (FastAPI):** Receives GitHub webhooks (with signature verification), issues runner registration tokens, and queues jobs in Redis.
- **Host Agent:** Polls the control plane for work, manages Firecracker microVMs, and forwards Firecracker logs to the logging pipeline when configured.
- Ensure host agents have permissions to create tap devices and bridges (requires `ip`/`iproute2`).
- **Cache Proxy:** Provides a simple artifact cache API backed by the filesystem with HMAC-signed tokens; drop-in replacement for a future MinIO/Ceph proxy.
- **Logging Pipeline:** Streams job logs into ClickHouse using JSONEachRow inserts.
- **Optional SSH/DNS Helpers:** Command snippets for exposing live SSH sessions and registering VM hostnames.

## Getting Started
1. Install dependencies:
   ```bash
   pip install -e .
   ```
2. Define environment variables for the control plane, host agent, cache proxy, and logging pipeline services (see inline comments in the settings classes for required keys, including `SMITH_GITHUB_WEBHOOK_SECRET` and `SMITH_CACHE_SHARED_SECRET`).
3. Launch services with UVicorn (example):
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

## Firecracker Assets
Use the helper script to download Firecracker kernel and root filesystem images:
```bash
python scripts/setup_firecracker_assets.py ./artifacts
```

## Roadmap
- Replace the simulator with real Firecracker lifecycle management.
- Integrate cache tokens and MinIO/Ceph backends.
- Harden authentication (JWT scoped per agent, webhook signature validation).
- Build a UI/CLI for monitoring jobs and searching logs.

Smith is a work in progress; contributions and suggestions are welcome.
