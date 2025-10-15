# Smith

Smith is an experimental platform that mirrors key ideas from Blacksmith.sh: an AWS-hosted control plane that orchestrates GitHub Actions jobs onto bare-metal hosts running Firecracker microVMs. This repository contains a prototype implementation that can be used as a learning tool or homelab foundation.

## Components
- **Control Plane (FastAPI):** Receives GitHub webhooks, issues runner registration tokens, and queues jobs in Redis.
- **Host Agent:** Polls the control plane for work, prepares Firecracker configs, and (currently) simulates microVM execution.
- **Cache Proxy:** Provides a simple artifact cache API backed by the filesystem; drop-in replacement for a future MinIO/Ceph proxy.
- **Logging Pipeline:** Streams job logs into ClickHouse using JSONEachRow inserts.
- **Optional SSH/DNS Helpers:** Command snippets for exposing live SSH sessions and registering VM hostnames.

## Getting Started
1. Install dependencies:
   ```bash
   pip install -e .
   ```
2. Copy `env.example` to `.env` and set the required environment variables for the control plane, host agent, cache proxy, and logging pipeline services.
3. Launch services with UVicorn (example):
   ```bash
   uvicorn smith.control_plane.main:app --reload
   uvicorn smith.cache_proxy.main:app --reload --port 8001
   uvicorn smith.logging_pipeline.main:app --reload --port 8002
   python -m smith.host_agent.main
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
