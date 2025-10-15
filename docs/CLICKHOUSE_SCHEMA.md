# ClickHouse Schema for Nimbus Logging

This document describes the required ClickHouse schema for the Nimbus logging pipeline.

## Table: ci_logs

The `ci_logs` table stores all log entries from job executions with org/repo boundaries for multi-tenant isolation.

### Schema

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
PARTITION BY toYYYYMM(ts)
SETTINGS index_granularity = 8192;
```

### Column Descriptions

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `job_id` | UInt64 | No | GitHub Actions job ID |
| `agent_id` | String | No | Nimbus host agent identifier |
| `org_id` | UInt64 | Yes | Organization/repository owner ID for multi-tenant isolation |
| `repo_id` | UInt64 | Yes | Repository ID for multi-tenant isolation |
| `level` | String | No | Log level: debug, info, warning, error, critical |
| `message` | String | No | Log message content |
| `ts` | DateTime64(3) | No | Log timestamp with millisecond precision |
| `inserted_at` | DateTime | No | When the log was inserted into ClickHouse |

### Indexes

The primary ordering key `(org_id, repo_id, job_id, ts)` ensures:
- Efficient queries filtered by organization
- Fast repo-scoped log retrieval
- Time-ordered logs within a job

### Partitioning

The table is partitioned by month (`toYYYYMM(ts)`) to:
- Enable efficient data retention policies
- Improve query performance for recent logs
- Allow easy dropping of old partitions

### Multi-Tenant Isolation

**CRITICAL FOR PRODUCTION:**

When exposing query endpoints to tenants, **ALWAYS** filter by `org_id` to prevent cross-organization log access:

```sql
-- Good: org-scoped query
SELECT * FROM ci_logs 
WHERE org_id = {tenant_org_id}
  AND job_id = {job_id}
ORDER BY ts DESC
LIMIT 100;

-- BAD: allows cross-org access
SELECT * FROM ci_logs 
WHERE job_id = {job_id}
ORDER BY ts DESC
LIMIT 100;
```

### Retention Policy (Optional)

To automatically drop old partitions:

```sql
-- Drop partitions older than 90 days
ALTER TABLE nimbus.ci_logs 
DROP PARTITION WHERE toDate(ts) < today() - INTERVAL 90 DAY;
```

Consider setting up a cron job or ClickHouse TTL for automatic cleanup:

```sql
-- Add TTL to table (drops data older than 90 days)
ALTER TABLE nimbus.ci_logs 
MODIFY TTL ts + INTERVAL 90 DAY;
```

### Sample Queries

**Logs for a specific job (org-scoped):**
```sql
SELECT job_id, agent_id, level, message, ts
FROM ci_logs
WHERE org_id = 12345
  AND job_id = 67890
ORDER BY ts DESC
LIMIT 100;
```

**Error logs for an organization:**
```sql
SELECT job_id, repo_id, message, ts
FROM ci_logs
WHERE org_id = 12345
  AND level = 'error'
  AND ts >= now() - INTERVAL 24 HOUR
ORDER BY ts DESC
LIMIT 50;
```

**Logs matching a pattern (org-scoped):**
```sql
SELECT job_id, message, ts
FROM ci_logs
WHERE org_id = 12345
  AND message ILIKE '%timeout%'
  AND ts >= now() - INTERVAL 7 DAY
ORDER BY ts DESC
LIMIT 100;
```

### Migration from Old Schema

If migrating from a schema without `org_id` and `repo_id`:

```sql
-- Add new columns
ALTER TABLE nimbus.ci_logs 
ADD COLUMN org_id Nullable(UInt64),
ADD COLUMN repo_id Nullable(UInt64);

-- Backfill from jobs table (if available)
-- This is an example - adjust based on your setup
ALTER TABLE nimbus.ci_logs 
UPDATE org_id = (SELECT repo_id FROM nimbus.jobs WHERE jobs.job_id = ci_logs.job_id LIMIT 1)
WHERE org_id IS NULL;
```

### Performance Tuning

For high-throughput logging:
- Consider using `Buffer` engine as a write buffer
- Increase `index_granularity` for large datasets
- Use `OPTIMIZE TABLE` periodically to merge parts
- Monitor partition size and adjust partitioning strategy

```sql
-- Check table statistics
SELECT 
    partition,
    sum(rows) as total_rows,
    formatReadableSize(sum(bytes_on_disk)) as size
FROM system.parts
WHERE table = 'ci_logs' AND active
GROUP BY partition
ORDER BY partition DESC;
```
