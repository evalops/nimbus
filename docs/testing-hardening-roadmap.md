# Testing & Coverage Hardening Roadmap

Nimbus currently lacks the test depth needed for a production control-plane and host-agent stack. The immediate focus areas below translate the red‑flag list into concrete milestones, owners, and acceptance criteria.

## 1. Baseline Metrics & Infrastructure

- **Task**: Fix `pytest` collection so `src.nimbus` imports resolve under `uv run`.
  - Add root `src/__init__.py` (done) and ensure CI sets `PYTHONPATH=.` or installs in editable mode.
  - Owners: Dev Productivity.
- **Task**: Enforce coverage collection in CI with `--cov=src/nimbus --cov-report=xml`.
  - Publish coverage diff to PRs and gate on thresholds.
- **Goal**: Establish current coverage report (blocked until import issue fixed).

## 2. Coverage Targets

- **Task**: Incrementally raise global line coverage from ~65% → 85%.
  - Prioritise untested critical paths: lease fencing, token mint/verify, snapshot boot, Redis queueing.
  - Track via module-level owners and weekly reporting.
- **Task**: Require ≥95% coverage for authn/authz & lease fencing modules.
  - Configure per-path coverage fail-under in `.coveragerc` or Pytest hook.
  - Extend suites in `tests/test_control_plane_security.py` and `tests/test_host_agent_retry.py`.

## 3. Property & Fuzz Testing

- **Task**: Add Hypothesis-powered property tests for:
  - Lease `try_acquire_job_lease` monotonic fencing.
  - Idempotent webhook handling across timestamp skew and duplicate delivery IDs.
  - Cache eviction quota accounting (bounded storage, org quotas).
- **Task**: Integrate libFuzzer/Atheris fuzzers for:
  - Webhook signature + JSON parsers.
  - Cache proxy key sanitiser.
  - ClickHouse ingestion payloads.
  - Run fuzzers nightly; add crash bucketing + corpus sync.

## 4. Threat Model & Policy Verification

- **Task**: Author STRIDE matrix covering control plane, host agent, caches, observability, and web.
  - Deliverable: `docs/threat-model.md` with mitigations, owner, residual risk.
- **Task**: Define OPA/Rego policies for RBAC + service account operations and add golden tests.
  - Build harness that loads policy bundles and runs allow/deny fixtures.
- **Task**: Bank security regression tests (step-up auth, deny-by-default, invalid tokens).

## 5. Egress Enforcement Validation

- **Task**: Build netns/iptables unit tests verifying OfflineEgressEnforcer rules:
  - Metadata deny-list (e.g., AWS/GCP metadata IPs).
  - Regex pack default deny logic.
  - Offline-mode allowed registry list.
- **Task**: Add red-team scenarios (DNS covert channels, `curl` inside Docker image, sidecar reachability) as automated integration tests.
  - Use container fixtures and monitored pcap/iptables counters.

## 6. GPU Isolation

- **Task**: Document MIG/GDS posture, NVML visibility scoping, CUDA MPS choices.
- **Task**: Enforce per-job GPU cgroups + `CUDA_VISIBLE_DEVICES` restriction.
- **Task**: Add integration tests simulating multi-GPU tenancy to ensure label scheduling honours exclusivity.

## 7. Supply Chain Enforcement

- **Task**: Formalise provenance policy (in-toto attestations, SLSA level, SBOM allow-list).
- **Task**: Enforce policy inside executor admission control:
  - Extend `ensure_provenance` to require attestation bundle verification (fail closed).
  - Add tests covering allowed/denied images, revoked keys, tampered SBOM.

## 8. Multi-tenant Data Isolation

- **Task**: Implement ClickHouse row-level security & quotas.
  - Add query wrapper enforcing org filters; write regression tests (positive/negative).
  - Configure per-org resource limits (max_threads, query_mem limit) and test under load.

## 9. DoS & Backpressure

- **Task**: Stress suites for control-plane rate limiting:
  - Simulate 10x normal webhook bursts, ensure leased backlog drains.
  - Chaos tests around Redis persistence loss + replay on restart.
  - Verify job spam from compromised repos triggers fencing/rate limits.

## 10. Idempotency & Replay Safety

- **Task**: Add acceptance tests for duplicate GitHub deliveries.
  - Verify job dedup keyed by `workflow_job.id` + attempt.
  - Ensure agents maintain exactly-once semantics even with lease expiry + retry.

## 11. Secrets & Key Management

- **Task**: Integrate Vault/KMS for token signing and secret storage.
  - Replace plain env secrets with Vault transit calls and rotation schedule.
  - Add automated rotation smoke tests and sealed-secret deployment pipeline.

## 12. Ops Fundamentals

- **Task**: Define and publish SLOs (dispatch latency, queue backlog) with monitoring hooks.
- **Task**: Establish semver release process + DB migration policy (zero-downtime).
- **Task**: Document backup/DR runbooks covering Postgres/ClickHouse (RPO/RTO tests).
- **Task**: Expand runbook drills and surface in `docs/operations.md`.

## Tracking & Execution

- Each section should map to epics in the project tracker with exit criteria.
- Weekly security/testing sync to review progress.
- Block “production ready” milestone until all critical items (coverage, threat model, egress tests, provenance enforcement, multi-tenant isolation) are closed.
