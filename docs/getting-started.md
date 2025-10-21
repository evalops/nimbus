# Getting Started with Nimbus

This guide walks through the minimum setup to run Nimbus locally or in a lab environment and highlights how to integrate with GitHub Actions.

## Prerequisites

- Python 3.12 with [uv](https://github.com/astral-sh/uv)
- PostgreSQL instances or schemas for the control plane, host agent state, cache metrics, and Docker cache metadata
- Redis for job queuing
- Firecracker binary, kernel, and rootfs images when running the host agent locally

## Bootstrap the Stack

1. Create a virtual environment and install Nimbus in editable mode:
   ```bash
   uv venv .venv
   uv pip install -e .
   ```
2. Provision databases or schemas and export the DSNs:
   ```bash
   export NIMBUS_DATABASE_URL="postgresql+asyncpg://<user>:<password>@db/nimbus_control"
   export NIMBUS_AGENT_STATE_DATABASE_URL="postgresql+asyncpg://<user>:<password>@db/nimbus_agent_state"
   export NIMBUS_CACHE_METRICS_DB="postgresql+psycopg://<user>:<password>@db/nimbus_cache_metrics"
   export NIMBUS_DOCKER_CACHE_DB_PATH="postgresql+psycopg://<user>:<password>@db/nimbus_docker_cache"
   ```
3. Define required secrets such as `NIMBUS_GITHUB_WEBHOOK_SECRET`, `NIMBUS_AGENT_TOKEN_SECRET`, `NIMBUS_CACHE_SHARED_SECRET`, and the host agent credentials.
4. Start the services:
   ```bash
   uvicorn nimbus.control_plane.main:app --reload
   uvicorn nimbus.cache_proxy.main:app --reload --port 8001
   uvicorn nimbus.logging_pipeline.main:app --reload --port 8002
   python -m nimbus.host_agent.main
   ```
5. Run the automated test suite to validate the installation:
   ```bash
   uv run pytest
   ```

## Using Nimbus with GitHub Actions

Point a job to Nimbus by specifying `runs-on: nimbus` in your workflow:

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
          # Your commands here
```

The control plane verifies webhook signatures (`X-Hub-Signature-256` plus `X-Hub-Signature-Timestamp`, default tolerance `300s` via `NIMBUS_WEBHOOK_TIMESTAMP_TOLERANCE`), enforces per-org rate limits, and hands jobs to host agents via DB-backed leases.

## Pre-built Job Runners

Nimbus publishes curated images for common workflows. Example: `nimbus/ai-eval-runner` bundles Node.js 20, `eval2otel`, and the `ollama` client for model evaluation pipelines. Submit jobs referencing the image and pass observability or model endpoints via environment variables.

## Frequently Used CLI Commands

```bash
# Recent jobs
python -m nimbus.cli.jobs recent --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --limit 10
python -m nimbus.cli.jobs recent --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --status running
python -m nimbus.cli.jobs recent --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --label gpu
python -m nimbus.cli.jobs recent --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --with-metadata

# Queue health
python -m nimbus.cli.jobs status --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET

# Logs for a job
python -m nimbus.cli.logs --logs-url http://localhost:8002 --job-id 12345 --limit 50

# Mint tokens
    python -m nimbus.cli.cache --secret $NIMBUS_CACHE_SHARED_SECRET --org-id 123 --ttl 3600
    python -m nimbus.cli.auth --agent-id agent-001 --secret $NIMBUS_AGENT_TOKEN_SECRET --ttl 3600
```

Labels prefixed with `param:` or `meta:` (for example `param:lr=0.001`, `meta:safety-review`) are captured as job metadata and show up via `--with-metadata` or the job APIs.

## Local Quickstart Example

If you just want to see Nimbus running end to end with docker compose, the helper script below will bootstrap a `.env` file, start the compose stack, and block until the control plane passes its health probe:

```bash
uv run python scripts/quickstart_compose.py
```

Key flags:

- `--force-bootstrap` regenerates the env file (helpful after rotating secrets).
- `--with-agent` starts the host agent profile; make sure Firecracker artifacts exist under `./artifacts` and `/dev/kvm` is available.
- `--no-detach` keeps `docker compose up` in the foreground so you can tail logs inline.

Once the script reports that the stack is ready, visit `http://127.0.0.1:5173` for the dashboard and `http://127.0.0.1:8000/healthz` for the control plane health payload. The generated `.env.local` file contains the secrets the stack is using; keep it safe if you plan to reuse those values.

## Next Steps

- Configure environment variables: see [Configuration](./configuration.md)
- Plan deployment and observability: see [Operations](./operations.md)
- Harden Firecracker and host agents: see [Firecracker Security Hardening](./FIRECRACKER_SECURITY.md)
