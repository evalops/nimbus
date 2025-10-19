# Nimbus Threat Model (STRIDE Baseline)

This document captures the initial STRIDE analysis for Nimbus components. It highlights current mitigations and the blockers that must be resolved before a production release.

## 1. System Overview

- **Assets**
  - GitHub webhook secrets, agent JWT/signing keys, cache tokens.
  - Job definitions, artifacts, logs, ClickHouse telemetry.
  - Rootfs images, Docker/GPU executor environments.
  - Compliance export logs, RBAC policy definitions.
- **Trust Boundaries**
  - Internet ▶️ Control Plane (GitHub webhooks, admin/API clients).
  - Control Plane ▶️ Redis/Postgres/ClickHouse.
  - Control Plane ▶️ Host Agents (lease issuance, fencing).
  - Host Agents ▶️ Executors (Firecracker, Docker, GPU).
  - Tenants ▶️ Cache Proxy / Docker Cache / Logging endpoints.

## 2. STRIDE Breakdown

| Component | Spoofing | Tampering | Repudiation | Information Disclosure | DoS | Elevation of Privilege |
|-----------|----------|-----------|-------------|------------------------|-----|------------------------|
| GitHub Webhook Ingress | ✅ HMAC + timestamp + delivery nonce. | ❌ Need replay fuzzing & idempotency tests. | ✅ Structured logging. | ✅ Payload minima, but fuzzing pending. | ⚠️ Risk of burst -> redis backlog. | ⚠️ No step-up auth for admin endpoints. |
| Job Lease Service | ✅ Fence tokens, agent auth. | ⚠️ Missing property tests for lease monotonicity. | ✅ Audit tables. | ⚠️ Lease data in Redis (no encryption). | ⚠️ Rate-limit coverage low. | ⚠️ Missing agent capability verification tests. |
| Cache Proxy | ✅ Bearer cache tokens. | ⚠️ Need fuzz tests for key sanitiser + eviction. | ✅ Request logging. | ⚠️ S3/local backend quota bypass risk. | ⚠️ Circuit breaker tuning untested. | ⚠️ Tokens scoped by org but no policy proofs. |
| Docker Cache | ✅ Token scope enforcement. | ⚠️ Metadata tamper via partial uploads. | ✅ Audit events. | ⚠️ Org isolation not fuzzed. | ⚠️ Potential blob storm. | ⚠️ No attestation enforcement. |
| Logging Pipeline | ✅ Cache token scope. | ⚠️ No fuzzing of ClickHouse payload. | ✅ Ingest logs. | ⚠️ Need row-level security enforcement tests. | ⚠️ Backpressure + batching thresholds untested. | ⚠️ Query policy lacks deny-by-default tests. |
| Host Agent | ✅ Control-plane JWTs. | ⚠️ Egress policy bypass surfaces (curl, DNS). | ✅ Job status logs. | ⚠️ GPU telemetry leaks (NVML, MIG). | ⚠️ Warm pool exhaustion -> DoS. | ⚠️ Supply-chain checks best-effort only. |
| Web Dashboard | ✅ SSO / RBAC (docs). | ⚠️ No permission matrix regression tests. | ✅ HTTP access logs. | ⚠️ Potential cross-tenant data leakage. | ⚠️ Unbounded queries vs ClickHouse. | ⚠️ UI step-up, scoped tokens not validated. |

Legend: ✅ covered, ⚠️ gap, ❌ missing mitigation.

## 3. Priority Gaps

1. **Policy Verification**
   - Formalise RBAC/OPA policies and create golden allow/deny fixture tests.
   - Add CI suite to run policy regression on every commit.

2. **Egress Enforcement**
   - Netns + iptables unit tests ensuring metadata endpoints and deny-list hits are blocked.
   - Red-team scenarios (DNS tunnelling, curl-in-image, sidecar pivot) automated in integration tests.

3. **Replay & Idempotency**
   - Property-based tests to ensure webhook replays do not duplicate jobs.
   - Agent lease state machine tests for monotonic fence tokens and exact-once completion semantics.

4. **Multi-tenant Isolation**
   - ClickHouse row-level security with regression harness.
   - Cache/Docker registries enforcing org quotas with adversarial testing.

5. **Secrets & Key Management**
   - Store secrets in Vault/KMS; rotate via automation; add dry-run restore tests.

## 4. Next Actions

- [ ] Produce OPA policy suite (`policy/` + `tests/policy`) with deny-by-default.
- [ ] Implement fuzz/property frameworks per `docs/testing-hardening-roadmap.md`.
- [ ] Add network namespace simulation tests validating OfflineEgressEnforcer.
- [ ] Document GPU sharing strategy (MIG/MPS) and enforce per-job restrictions.
- [ ] Update runbooks with SLOs, DR, backup procedures.

This document should be updated as mitigations land. Once all ⚠️ and ❌ items are addressed, review with security engineering before declaring the system production-ready.
