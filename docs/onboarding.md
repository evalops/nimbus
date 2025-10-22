# Nimbus Onboarding Playbook

New to Nimbus? This quick-start itinerary walks you from zero to your first successful evaluation run in roughly 30 minutes.

## 1. Bootstrap the control plane

1. Make sure Docker (or Podman) is installed and running.
2. Clone the repository and copy the sample environment file:

   ```bash
   git clone https://github.com/evalops/nimbus.git
   cd nimbus
   cp compose.env.sample .env
   ```

3. Launch the core services:

   ```bash
   docker compose up -d control-plane cache-proxy docker-cache logging-pipeline
   ```

   The services expose ports:

   - Control plane API/dashboard: `http://localhost:8000`
   - Cache proxy: `http://localhost:8001`
   - Docker cache: `http://localhost:8003`
   - Logging pipeline: `http://localhost:8002`

4. Open the dashboard at `http://localhost:5173` (or whatever the `web` dev server prints) and follow the Settings wizard to issue an admin token.

## 2. Register your first host agent

1. Mint a dashboard agent token from **Settings → Agent Tokens → “Mint token”**.
2. Start the host agent with the one-liner (replace placeholders):

   ```bash
   uv run python -m nimbus.host_agent \
     --control-plane https://your-control-plane \
     --token <agent-token> \
     --cache-proxy https://your-cache-proxy
   ```

   On macOS/Linux you can use the packaged script `./scripts/bootstrap_agent.sh` which prompts for the values.

3. The agent checks in automatically; you should see it listed under **Agents** with a green heartbeat.

## 3. Run a sample evaluation

1. Seed the control plane with the example workload:

   ```bash
   uv run python scripts/demo/seed_repo.py
   ```

2. Kick off the evaluation:

   ```bash
   uv run python scripts/demo/run_eval.py --repo acme/example --suite default
   ```

3. Track progress in the dashboard overview. Nimbus fetches cache analytics, resource telemetry, and metadata summaries out of the box.

## 4. Connect your own repository

1. Configure the GitHub app credentials in `.env` and rerun `docker compose up`.
2. Use the **Repositories** view to register your repo + evaluation suite mapping.
3. Push a PR or hit the API to trigger an eval. Results stream to the dashboard and webhook callbacks.

## 5. Production hardening checklist

- ✅ Provision Redis/Postgres from your infra provider (RDS, CloudSQL, etc.) and point `.env`.
- ✅ Stand up the control plane via Terraform or Helm (templates in `deploy/`).
- ✅ Configure TLS (terminate at a reverse proxy or load balancer).
- ✅ Schedule nightly `nimbus.cli.report overview` runs and archive the JSON for auditing.
- ✅ Enable OpenTelemetry export to your tracing backend.

With this workflow you can hand prospects (or teammates) a replicable starter path and remove the usual “self-hosted friction” objections. For a deeper migration from GitHub Actions, read [docs/github-actions-migration.md](./github-actions-migration.md).
