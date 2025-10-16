# Pre-Pilot Readiness Summary

Current assessment of Nimbus features required for a production pilot.

## Legend

| Status | Meaning |
| --- | --- |
| ✅ Complete | Implemented and covered by code/tests in the repo |
| ⚠️ Partial | Core behavior exists but needs additional hardening |
| 🚧 Planned | Not yet implemented |

## Control Plane & Runner Lifecycle

| Topic | Status | Notes |
| --- | --- | --- |
| Lease fencing | ✅ Complete | `control_plane/jobs.py` and `db.py` enforce DB-backed fence tokens; host agent renews leases with jitter. |
| Idempotent teardown | ✅ Complete | Host agent persists job state in `AgentStateStore` and runs `reap_stale_resources()` on startup. |
| Webhook replay protection | ⚠️ Partial | Delivery IDs are de-duplicated in Redis (`control_plane/app.py`), but payload timestamp validation is still pending. |
| SSH session cleanup | ✅ Complete | Background task expires stale SSH sessions every minute. |

## Multi-Tenant Isolation

| Topic | Status | Notes |
| --- | --- | --- |
| Cache token scopes | ⚠️ Partial | Cache proxy, logging pipeline, and Docker cache validate `pull/push` scopes, but control plane still mints `read_write` tokens (no scoped issuance yet). |
| Docker registry boundaries | ✅ Complete | All registry endpoints call `validate_repository_access()` and enforce org prefixes/ownership checks. Legacy non-prefixed repos still tolerated but logged. |
| Logs privacy | ✅ Complete | Logging pipeline requires tokens, re-scopes all entries to the authenticated org, and enforces org filters on queries. |

## Security Hardening

| Topic | Status | Notes |
| --- | --- | --- |
| Firecracker jailer & seccomp | 🚧 Planned | `docs/FIRECRACKER_SECURITY.md` captures the rollout plan; host agent currently only warns when running with excessive capabilities. |
| Capability dropping | ⚠️ Partial | `host_agent/security.py` provides checks and helpers, but production deployments still need the privileged wrapper script. |
| Trusted proxy handling | ⚠️ Partial | `control_plane/app.py` validates `X-Forwarded-*` against configured CIDRs, but defaults remain permissive. |
| Key rotation | 🚧 Planned | Agent/control-plane tokens exist; no JWKS or rotation workflow yet. |

## Reliability & Performance

| Topic | Status | Notes |
| --- | --- | --- |
| Distributed org rate limiting | ✅ Complete | Redis-backed limiter (`common/ratelimit.py`) enforces per-org quotas on webhook ingestion. |
| Rootfs attestation | 🚧 Planned | Rootfs tooling exists but hashes are not tracked in job metadata yet. |
| Performance tuning | 🚧 Planned | No automated vCPU pinning/NUMA tuning or benchmarking harness. |
| Snapshot boot | 🚧 Planned | Snapshot execution path not started. |

## Operational Gaps

- **Metrics exposure**: Service `/metrics` endpoints remain unauthenticated; operators should firewall them until auth is added.
- **Cache token issuance**: Introduce scoped cache token minting (e.g., `pull:org-123`) once GitHub workflow metadata contains the target scopes.
- **Webhook timestamp checks**: Enforce a signed timestamp window to complement delivery ID replay protection.
- **Documentation**: Keep this file as the single source for readiness; deprecated documents have been removed.

---

_Last reviewed: 2025-10-16_
