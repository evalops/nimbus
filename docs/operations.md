# Operations Guide

This guide covers day-two operations: deployment recipes, observability hooks, and production hardening.

## Deployment Recipes

### Local Development Stack

1. Export required environment variables (see [Configuration](./configuration.md)).
2. Start the APIs with uv:
   ```bash
   uv run uvicorn nimbus.control_plane.main:app --host 0.0.0.0 --port 8000 --reload
   uv run uvicorn nimbus.cache_proxy.main:app --host 0.0.0.0 --port 8001 --reload
   uv run uvicorn nimbus.logging_pipeline.main:app --host 0.0.0.0 --port 8002 --reload
   ```
3. Launch a host agent once kernel/rootfs assets are in place:
   ```bash
   uv run python -m nimbus.host_agent.main
   ```

### Remote Host Agent

- Install the Nimbus package on the target host (`uv pip install .` or copy the project).
- Provision Firecracker assets with `scripts/setup_firecracker_assets.py`.
- Export `NIMBUS_CONTROL_PLANE_URL`, `NIMBUS_CONTROL_PLANE_TOKEN`, and networking variables.
- Run `python -m nimbus.host_agent.main` under a supervisor (systemd, supervisord, etc.).

### Minimal Cache Proxy

```bash
export NIMBUS_CACHE_SHARED_SECRET="super-secret"
uv run uvicorn nimbus.cache_proxy.main:app --host 0.0.0.0 --port 8001
```

Configure S3 fields when delegating storage to a remote backend.

## Firecracker Assets & Security

- Download kernel/rootfs artifacts: `python scripts/setup_firecracker_assets.py ./artifacts`
- Install jailer, seccomp profiles, and capability dropping via `sudo bash scripts/install-security.sh`
- Configure environment:
  ```bash
  cat >> .env <<'EOF'
  NIMBUS_JAILER_BIN=/usr/local/bin/jailer
  NIMBUS_SECCOMP_FILTER=/etc/nimbus/seccomp-$(uname -m).json
  NIMBUS_JAILER_UID=$(id -u nimbus)
  NIMBUS_JAILER_GID=$(id -g nimbus)
  NIMBUS_JAILER_CHROOT_BASE=/srv/jailer
  EOF
  ```
- Start the agent through the privileged wrapper:
  ```bash
  sudo /usr/local/bin/nimbus-privileged-setup.sh python -m nimbus.host_agent.main
  ```

See [Firecracker Security Hardening](./FIRECRACKER_SECURITY.md) for jailer, seccomp, and capability guidance.

## Observability

- Metrics endpoints require either `NIMBUS_*_METRICS_TOKEN` plus an `Authorization: Bearer` header or loopback access.
- Structured logging uses `structlog`; adjust verbosity with `NIMBUS_LOG_LEVEL`.
- Enable OpenTelemetry export with `NIMBUS_OTEL_EXPORTER_ENDPOINT`, `NIMBUS_OTEL_EXPORTER_HEADERS`, and `NIMBUS_OTEL_SAMPLER_RATIO`.
- Set `NIMBUS_METADATA_SINK_URL` to the logging pipeline (`http://logging-pipeline:8090`) so job metadata is forwarded to ClickHouse.
- Configure metadata retention via `NIMBUS_METADATA_RETENTION_DAYS` (defaults to 90) to automatically prune historical metadata rows.
- Supply `metadata_key` when calling `/api/observability/orgs` (or via the dashboard control) to surface per-tenant metadata buckets and success rates.
- Define default metadata keys with `NIMBUS_METADATA_DEFAULT_KEYS=lr,batch` to prefetch analytics served from `/api/jobs/metadata/presets`.
- Provide explicit database URLs such as `NIMBUS_CACHE_METRICS_DB` and `NIMBUS_DOCKER_CACHE_DB_PATH`; these are required and no longer fall back to localhost defaults.

## Policy Enforcement

Set `NIMBUS_JOB_POLICY_PATH` to a YAML document to run admission checks on incoming GitHub workflow jobs. The policy can reject forbidden labels, require safety reviews, restrict execution to approved repositories, or block risky workflow titles. See [Policy-as-Code](./policy-as-code.md) for supported fields and examples.

## Reporting CLI

Generate operational snapshots from the CLI:

- Org analytics: `python -m nimbus.cli.report orgs --base-url http://localhost:8000 --token $NIMBUS_ADMIN_JWT`
- Jobs summary (includes top metadata tags): `python -m nimbus.cli.report jobs --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET`
- Jobs summary filtered by metadata: `python -m nimbus.cli.report jobs --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --metadata-key lr --metadata-value 0.1`
- Metadata histogram: `python -m nimbus.cli.report metadata --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --key lr`
- Metadata trend: `python -m nimbus.cli.report metadata --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --key lr --trend --bucket-hours 6`
- Metadata presets export: `python -m nimbus.cli.report metadata-presets --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --json --output presets.json`
- Cache usage: `python -m nimbus.cli.report cache --cache-url http://localhost:8001`
- Log ingestion overview: `python -m nimbus.cli.report logs --logs-url http://localhost:8002 --job-id 12345 --limit 50`
- Full overview: `python -m nimbus.cli.report overview --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --cache-url http://localhost:8001 --logs-url http://localhost:8002`
- Full overview filtered by metadata: `python -m nimbus.cli.report overview --base-url http://localhost:8000 --token $NIMBUS_JWT_SECRET --cache-url http://localhost:8001 --logs-url http://localhost:8002 --job-metadata-key lr --job-metadata-value 0.1`

## Production Checklist

Nimbus tracks major hardening milestones in the project backlog. Highlights:

- Lease fencing, idempotent cleanup, distributed rate limiting, and org-scoped boundaries are implemented.
- Webhook timestamp validation, scoped cache tokens, and capability hardening require correct configuration to stay effective.
- Rootfs attestation, jailer rollout, and performance tuning remain ongoing.

### Multi-Tenant Configuration

```bash
NIMBUS_CACHE_SHARED_SECRET="<secure-secret>"
NIMBUS_JOB_LEASE_TTL=300
NIMBUS_ORG_JOB_RATE_LIMIT=100
NIMBUS_ORG_RATE_INTERVAL=60
```

Ensure Docker repositories follow the `org-{id}/` prefix to enforce ownership checks.

### Monitoring

Prometheus scrape points:

- Control plane: `http://localhost:8000/metrics`
- Host agent: `http://localhost:9460/metrics`
- Cache proxy: `http://localhost:8001/metrics`

Key metrics:

- `nimbus_control_plane_webhook_replays_blocked`
- `nimbus_control_plane_org_rate_limits_hit`
- `nimbus_host_agent_job_timeouts_total`
- `nimbus_host_agent_lease_errors_total`
- `nimbus_cache_evictions_total`

### ClickHouse Schema

See [CLICKHOUSE_SCHEMA.md](./CLICKHOUSE_SCHEMA.md) for the canonical DDL:

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

## Additional Resources

- [Configuration Reference](./configuration.md)
- [Getting Started](./getting-started.md)
- [Firecracker Security Hardening](./FIRECRACKER_SECURITY.md)
- [Runbook](./runbook.md)
- [Policy-as-Code](./policy-as-code.md)
- [Onboarding Playbook](./onboarding.md)
- [GitHub Actions Migration Guide](./github-actions-migration.md)
- [ROI Calculator](./roi-calculator.md)
- Job metadata tagging: add `param:`/`meta:` labels to workflows so operators can inspect hyperparameters via `nimbus.cli.jobs --with-metadata`.
