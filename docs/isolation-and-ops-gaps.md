# Isolation, Supply Chain, and Operational Gaps

This document inventories the remaining blockers before Nimbus can be considered production ready. Each section captures the gap, the required remediation, and suggested validation.

## 1. GPU Isolation

- **Current State**
  - Executors allow multiple tenants to target the same physical GPU without MIG partitioning or per-job cgroup constraints.
  - NVML queries leak topology and utilisation data for the whole device.
  - No documentation on MIG/GDS strategy or CUDA MPS usage.
- **Actions**
  1. Decide on sharing model: exclusive GPU per job vs MIG slices vs CUDA MPS.
  2. Implement per-job GPU cgroups (`nvidia-container-runtime` device plugins) and enforce via scheduler labels.
  3. Mask NVML visibility to allocated devices only; disable `nvidia-smi` unless scoped.
  4. Document operational guidance (MIG layout, monitoring, fallback path).
- **Validation**
  - Integration tests that schedule simultaneous GPU jobs verifying isolation and denying cross-tenant allocation.
  - Security tests probing for device enumeration or bus snooping from a tenant container.

## 2. Supply Chain & Provenance Enforcement

- **Current State**
  - `ensure_provenance` is advisory; failures can be bypassed (best-effort).
  - No policy describing acceptable attestations/SBOM characteristics.
  - Executors do not require in-toto/SLSA attestations before running images.
- **Actions**
  1. Define policy: required attestations, acceptable builders, SBOM hash allow-list.
  2. Integrate cosign/in-toto verification at lease time (fail closed if verification fails).
  3. Store trusted roots/certificates in Vault or equivalent HSM-backed store.
  4. Create regression tests covering valid, expired, tampered, and missing attestations.

## 3. Multi-tenant Data Isolation

- **Current State**
  - ClickHouse queries rely on client-side filters; no row-level security across the board.
  - Cache/Docker registry quotas exist but lack stress tests.
  - Logging APIs do not enforce per-org resource limits (threads/memory) by default.
- **Actions**
  1. Add ClickHouse RLS policies; enforce via service user and query templates.
  2. Implement per-org query rate and resource limits (max_threads, memory usage, timeout).
  3. Extend cache/registry integration tests to simulate cross-org access attempts.
  4. Add UI/CLI end-to-end tests ensuring tenants cannot view foreign repos/logs.

## 4. DoS & Backpressure Resilience

- **Current State**
  - Rate limits exist but long-lived backlog, redis eviction, and job spam scenarios untested.
  - Redis durability under AOF/RDB loss and replay not validated.
  - Control plane does not surface metrics for backlog drain SLO monitoring.
- **Actions**
  1. Build load tests simulating webhook storms, agent churn, and backlog recovery.
  2. Implement dead-letter queues/alerts for stuck jobs.
  3. Validate Redis persistence and recovery strategy with chaos testing.
  4. Add queue depth, lease latency, and backlog SLO dashboards + alerts.

## 5. Secrets & Key Management

- **Current State**
  - Secrets live in `.env`/environment variables; rotation manual.
  - Tokens minted locally without HSM or Vault integration.
- **Actions**
  1. Integrate HashiCorp Vault/KMS for secret storage and token signing.
  2. Automate rotation cadence with audit logging.
  3. Provide sealed secret deployment path for agents (e.g., Kubernetes CSR + sealed secrets).
  4. Add tests that confirm components refuse to start with stale/disabled keys.

## 6. Operational Readiness

- **Current State**
  - No published SLOs/error budgets.
  - Release cadence undefined; DB migrations lack zero-downtime guidance.
  - Backups/restore playbooks missing for Postgres and ClickHouse.
  - Runbook drills not documented.
- **Actions**
  1. Define SLOs (dispatch latency, lease success rate, cache hit ratio) and track via dashboards.
  2. Adopt semantic versioning, changelog, and migration policy (blue/green, rolling).
  3. Document backup/DR procedures with tested RPO/RTO targets.
  4. Extend `docs/operations.md` with runbooks, on-call rotation, and drill frequency.

## 7. Verification Plan

- Create a quarterly security/ops review ensuring all sections meet acceptance tests.
- Add CI checks gating merges on presence of policy tests, egress tests, and provenance enforcement.
- Track remediation issues in project board with owners and due dates.
