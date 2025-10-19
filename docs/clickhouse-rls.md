# ClickHouse RLS Deployment Notes

Nimbus needs real row-level-security in ClickHouse before the logging API can be considered multi-tenant. Infrastructure teams should run the following DDL via `clickhouse-client` (or via your usual migration runner). This repo intentionally keeps secrets out – user creation happens in your secure environment.

```sql
CREATE DATABASE IF NOT EXISTS nimbus;

CREATE TABLE IF NOT EXISTS nimbus.job_logs
(
    ts DateTime64(3, 'UTC'),
    org_id LowCardinality(String),
    job_id String,
    level LowCardinality(String),
    msg String,
    kv Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (org_id, ts, job_id);

CREATE ROLE IF NOT EXISTS nimbus_writer;
CREATE ROLE IF NOT EXISTS nimbus_reader;

CREATE ROW POLICY IF NOT EXISTS job_logs_rls
    ON nimbus.job_logs FOR SELECT
    USING org_id = currentUser()
    TO nimbus_reader;

GRANT SELECT ON nimbus.job_logs TO nimbus_reader;
GRANT INSERT ON nimbus.job_logs TO nimbus_writer;
```

User provisioning is out-of-band. The logging service assumes:

- Query user: `USERNAME == org_id` (e.g. `acme`) with role `nimbus_reader`
- Ingest user: `USERNAME == f"{org_id}_writer"` (e.g. `acme_writer`) with role `nimbus_writer`

If you prefer a different mapping (e.g. using `SET evalops_tenant_id` in session settings), adjust the policy accordingly.

**Next steps:**

1. Store per-tenant credentials in Vault/KMS and plumb into the service via the `NIMBUS_CLICKHOUSE_QUERY_USER_TEMPLATE` and `NIMBUS_CLICKHOUSE_QUERY_PASSWORD_TEMPLATE` settings.
2. After applying the SQL above, run the integration tests in `tests/policy/test_logging_tenant_scope.py` against a dedicated ClickHouse instance to validate deny-by-default behaviour.
