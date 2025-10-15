# Operational Runbook

## Agent Token Rotation

1. **List inventory** – run `python -m nimbus.cli.admin tokens list --base-url <control-plane-url> --admin-token <jwt>` to view active agent tokens. Add `--history-limit 10` to include recent rotation audit records.
2. **Rotate token** – run `python -m nimbus.cli.admin tokens rotate --base-url <control-plane-url> --admin-token <jwt> --agent-id <agent> --ttl 3600`. The command prints the new bearer token and TTL; distribute it securely to the host.
3. **Verify** – call `python -m nimbus.cli.report tokens --base-url <control-plane-url> --token <jwt>` to confirm the latest version and check for expired agents.
4. **Rate limit handling** – rotations are throttled (defaults: 15 per 60s). If the API returns HTTP 429, wait for the interval to elapse before retrying or lower your burst.

## Responding to Watchdog Events

1. **Monitor metrics** – scrape the host agent metrics endpoint (defaults: `:9460/metrics`). Pay attention to:
   - `nimbus_host_agent_job_timeouts_total` – cumulative watchdog terminations.
   - `nimbus_host_agent_last_timeout_timestamp` – UNIX timestamp of the most recent timeout.
2. **Inspect logs** – query the logging pipeline for the affected job: `python -m nimbus.cli.report logs --logs-url <logging-url> --job-id <job>`.
3. **Check cache artifacts** – ensure partial outputs did not persist by verifying cache keys via `python -m nimbus.cli.report cache ...`.
4. **Adjust timeout** – update `NIMBUS_JOB_TIMEOUT` on the host agent if legitimate workloads exceed the default window and redeploy the agent.

## ClickHouse Recovery

1. **Detect ingestion failures** – monitor `nimbus_logging_clickhouse_errors_total` and `nimbus_logging_batch_latency_seconds` on the logging pipeline metrics endpoint.
2. **Validate connectivity** – use the `/status` endpoint (`curl <logging-url>/status`) to confirm ClickHouse URL and table configuration.
3. **Drain backlog** – the pipeline batches rows in memory; restart the logging service after restoring ClickHouse availability to replay pending batches.
4. **Post-recovery check** – run `python -m nimbus.cli.report logs --logs-url <logging-url> --limit 10` to ensure fresh entries are ingested and queries succeed.
