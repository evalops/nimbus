# ClickHouse Tenant Isolation and RLS

Nimbus relies on ClickHouse to store job telemetry. Before declaring the platform production ready we must enforce tenant isolation at the query layer.

## Current Gaps

- The logging API relies on caller-supplied filters. There is no ClickHouse-side row-level security policy preventing a compromised service account from querying other organizations.
- No quotas or per-tenant limits on `max_threads`, memory, or query duration. A noisy neighbor can starve the system.
- There is no regression suite verifying deny-by-default behavior or ensuring projections are applied consistently.

## Work Items

1. **Row-Level Security Policies**
   - Create ClickHouse `ROW POLICY` definitions keyed by `org_id` and attach them to the service user used by `LoggingIngestSettings`.
   - Adopt separate users for ingestion vs query to limit damage scope.
   - Document policy deployment in `docs/operations.md` and generate fixtures for new migrations.

2. **Scoped Query Execution**
   - Update the logging pipeline to use prepared statements that include RLS tokens (e.g., session-level `SET` for org context).
   - Add integration tests that attempt cross-org queries and expect rejection.

3. **Quota Configuration**
   - Define per-org settings (`max_threads`, `max_memory_usage`, `max_execution_time`) via ClickHouse profiles.
   - Monitor and alert on quota breaches.

4. **Test Harness**
   - Extend the policy tests to spin up a ClickHouse container with the RLS rules applied and verify deny/allow fixtures.
   - Fuzz query parameters (contains, limit) to ensure the service wrapper does not bypass restrictions.

5. **Operational Readiness**
   - Add runbooks for rotating ClickHouse user credentials and policy changes.
   - Document fallback / emergency access procedures with auditing requirements.

Until these controls are in place we must treat the logging pipeline as single-tenant. This document tracks progress on closing the gap.
