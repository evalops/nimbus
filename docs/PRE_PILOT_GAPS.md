# Pre-Pilot Gaps & Risk Mitigation

Critical issues to address before production pilot deployment.

## 1. Runner Lifecycle + Failure Modes

### Lease Fencing
**Status:** ❌ Not Implemented  
**Priority:** P0 (Critical)

**Problem:** Jobs could be claimed twice during Redis hiccups or network partitions.

**Solution:**
- Implement lease record with version + TTL in database
- Add heartbeat renewal mechanism
- Persist "fence token" in DB that must match for job operations
- Agent validates fence token before VM operations

**Implementation Tasks:**
- [ ] Add lease table to database schema with version field
- [ ] Implement heartbeat renewal loop in host agent
- [ ] Add fence token validation before VM start/stop operations
- [ ] Add integration test for concurrent lease attempts

---

### Idempotent Teardown
**Status:** ⚠️ Partial (basic cleanup exists)  
**Priority:** P0 (Critical)

**Problem:** Incomplete cleanup on agent crash leaves orphaned VMs, network taps, and runners.

**Solution:**
- Implement cleanup sequence: VM kill → tap cleanup → runner deregistration
- On agent restart, run reaper that scans for stale resources by label prefix
- Make all cleanup operations idempotent

**Implementation Tasks:**
- [ ] Add reaper function that runs on agent startup
- [ ] Implement stale VM detection (check for VMs with nimbus prefix)
- [ ] Implement stale tap device cleanup
- [ ] Add GitHub runner deregistration for orphaned runners
- [ ] Make all cleanup operations idempotent (safe to retry)
- [ ] Add system test for crash recovery

---

### Webhook Replay Protection
**Status:** ✅ Signature verification exists  
**Priority:** P1 (High)

**Problem:** Webhook replay attacks could trigger duplicate job runs.

**Solution:**
- Add replay window check (5-10 minute window)
- Implement nonce cache (Redis-backed, TTL matches window)
- Reject webhooks outside time window or with seen nonce

**Implementation Tasks:**
- [ ] Add timestamp validation (reject if >10m old)
- [ ] Implement nonce cache in Redis
- [ ] Add nonce to webhook payload signature
- [ ] Add test for replay protection

---

## 2. Multi-Tenant Hardening

### Cache Token Scopes
**Status:** ⚠️ Partial (HMAC exists, no scopes)  
**Priority:** P0 (Critical)

**Problem:** Current cache tokens don't enforce read/write separation or org boundaries.

**Solution:**
- Add scopes to cache tokens: `pull:org-X`, `push:org-X`
- Implement per-org namespace on disk/S3 keys (`{org_id}/{key}`)
- Validate scope on every cache operation

**Implementation Tasks:**
- [ ] Add `scopes` field to cache token structure
- [ ] Update cache token minting to include scopes
- [ ] Update cache proxy to validate scopes on GET/PUT
- [ ] Rewrite storage keys to include org_id prefix
- [ ] Add cross-org access test (should fail)

---

### Docker Layer Cache Registry Boundaries
**Status:** ❌ Not Implemented  
**Priority:** P0 (Critical)

**Problem:** Docker registry doesn't enforce org boundaries or implement proper OCI spec.

**Solution:**
- Store sha256 digest → path mapping with org_id
- Enforce max-bytes per org
- Implement range requests for layer pulls
- Add content deduplication

**Implementation Tasks:**
- [ ] Add org_id to blob metadata table
- [ ] Implement org-level storage quotas
- [ ] Add range request support (HTTP 206 Partial Content)
- [ ] Implement content-addressable deduplication
- [ ] Add OCI distribution spec compliance tests

---

### Logs Privacy & Isolation
**Status:** ⚠️ Partial (logs ingested, no boundaries)  
**Priority:** P0 (Critical)

**Problem:** ClickHouse logs don't enforce org/repo boundaries.

**Solution:**
- Add org_id, repo_id, job_id, runner_id to ClickHouse schema
- Enforce row-level filters on ingest path
- Add query-time validation if exposing SQL interface

**Implementation Tasks:**
- [ ] Update ClickHouse schema to include org_id, repo_id
- [ ] Update log ingest to extract and validate org context
- [ ] Add row-level security if exposing SQL queries
- [ ] Add test for cross-org log isolation

---

## 3. Reproducibility & Performance

### Rootfs Content Addressing
**Status:** ⚠️ Partial (versions exist, no attestation)  
**Priority:** P1 (High)

**Problem:** Can't verify which rootfs actually booted; hard to debug eval drift.

**Solution:**
- Hash rootfs + overlays for content addressing
- Store hash in job metadata
- Attest booted image via agent metadata

**Implementation Tasks:**
- [ ] Add hash computation to rootfs build pipeline
- [ ] Store rootfs_hash in job metadata
- [ ] Add agent metadata reporting of booted rootfs
- [ ] Add verification tool for rootfs integrity

---

### Performance Knobs
**Status:** ❌ Not Implemented  
**Priority:** P1 (High)

**Problem:** Default Firecracker config may have variable performance.

**Solution:**
- vCPU pinning for consistent performance
- cgroup quotas for resource isolation
- NUMA awareness for multi-socket hosts
- Disable ballooning for predictability

**Implementation Tasks:**
- [ ] Add vCPU pinning configuration
- [ ] Implement cgroup quota settings
- [ ] Add NUMA topology detection
- [ ] Add Firecracker config generator with perf defaults
- [ ] Add performance benchmarking test suite

---

### Snapshot Boot (Stretch Goal)
**Status:** ❌ Not Implemented  
**Priority:** P2 (Nice to have)

**Problem:** Cold start time adds latency to job start.

**Solution:**
- Pre-boot minimal rootfs snapshot
- Load snapshot instead of full boot
- Target <100ms VM ready time

**Implementation Tasks:**
- [ ] Research Firecracker snapshot API
- [ ] Create minimal pre-booted snapshot
- [ ] Implement snapshot load path in agent
- [ ] Benchmark snapshot vs cold boot times

---

## 4. Security Posture

### Seccomp & Jailer
**Status:** ❌ Not Implemented  
**Priority:** P0 (Critical)

**Problem:** Firecracker not running with security hardening.

**Solution:**
- Run FC binary under jailer with seccomp profile
- Drop unnecessary capabilities for agent process
- Network namespace per VM
- Tap namespacing with unique IDs (`nimbus-{shortid}`)

**Implementation Tasks:**
- [ ] Configure Firecracker jailer
- [ ] Add seccomp profile for jailer
- [ ] Drop agent capabilities (CAP_NET_ADMIN only when needed)
- [ ] Implement network namespace per VM
- [ ] Update tap naming to include unique ID
- [ ] Add security audit test

---

### Key Handling & Rotation
**Status:** ⚠️ Partial (keys stored, not rotated)  
**Priority:** P0 (Critical)

**Problem:** GitHub App private key could leak in logs; no key rotation.

**Solution:**
- Ensure private key never touches logs
- Add key rotation support with key-ID headers
- Publish JWKS-style keyset for agents
- Implement key version in JWT tokens

**Implementation Tasks:**
- [ ] Audit all log statements for key leakage
- [ ] Add key-ID to JWT header
- [ ] Implement multi-key validation (current + previous)
- [ ] Create JWKS endpoint for agent key verification
- [ ] Add key rotation procedure documentation
- [ ] Implement automated key redaction in logs

---

### Rate Limiting
**Status:** ⚠️ Partial (mint RL exists)  
**Priority:** P1 (High)

**Problem:** No per-org rate limiting; no backoff on GitHub API.

**Solution:**
- Add per-org rate limits
- Implement exponential backoff on GitHub install-token fetch
- Add circuit breaker for GitHub API failures

**Implementation Tasks:**
- [ ] Implement per-org rate limiting in control plane
- [ ] Add exponential backoff for GitHub API calls
- [ ] Implement circuit breaker for GitHub API
- [ ] Add rate limit metrics and monitoring
- [ ] Add test for rate limit enforcement

---

## Priority Matrix

### P0 - Must Fix Before Pilot
1. Lease fencing
2. Idempotent teardown
3. Cache token scopes
4. Docker registry org boundaries
5. Logs privacy
6. Seccomp & jailer
7. Key handling audit

### P1 - Should Fix Before Scale
1. Webhook replay protection
2. Rootfs attestation
3. Performance knobs
4. Per-org rate limiting

### P2 - Nice to Have
1. Snapshot boot

---

## Tracking

**Created:** 2025-10-15  
**Target Pilot Date:** TBD  
**Owner:** TBD

### Status Overview
- ❌ Not Started: 8 items
- ⚠️ Partial: 6 items
- ✅ Complete: 1 item
