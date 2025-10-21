CREATE DATABASE IF NOT EXISTS nimbus;

CREATE TABLE IF NOT EXISTS nimbus.job_logs
(
    ts DateTime64(6, 'UTC') DEFAULT now('UTC'),
    org_id UInt64,
    repo_id Nullable(UInt64),
    job_id UInt64,
    level LowCardinality(String),
    message String,
    agent_id LowCardinality(String),
    attributes Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (org_id, repo_id, ts, job_id);

CREATE ROLE IF NOT EXISTS nimbus_writer;
CREATE ROLE IF NOT EXISTS nimbus_reader;

CREATE ROW POLICY IF NOT EXISTS job_logs_rls
    ON nimbus.job_logs
    FOR SELECT
    USING org_id = toUInt64OrZero(currentSetting('evalops_tenant_id', '0'))
    TO nimbus_reader;

GRANT SELECT ON nimbus.job_logs TO nimbus_reader;
GRANT INSERT ON nimbus.job_logs TO nimbus_writer;
