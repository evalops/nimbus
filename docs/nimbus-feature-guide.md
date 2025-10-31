# Nimbus Feature Guide

This document explains the new platform capabilities that extend Nimbus beyond the baseline GitHub-compatible runner experience. Each section describes the architecture, configuration, and operational workflows for the feature set.

## Near-Runner Cache

The host agent now embeds a lightweight HTTP cache alongside every worker. Two access modes are supported:

1. **Loopback HTTP** – Jobs can use the advertised `cache.endpoint.*` metadata keys to reach the cache from either the host or guest network.
2. **Virtio-fs passthrough** – When `virtiofsd` is available the cache directory is mounted directly into Firecracker guests, allowing POSIX access.

### Lifecycle

- The `NearRunnerCacheManager` spins up a FastAPI app on a dedicated port as part of the host agent boot sequence.
- Cache tokens minted by the control plane guard every request; scope is validated per organization and operation (push/pull).
- Writes are persisted to the local cache directory and optionally mirrored to S3 for durability.
- Reads fall back to S3 automatically when the local artifact is missing.
- When virtio-fs is enabled, the Firecracker launcher starts `virtiofsd` alongside the microVM and configures the device over MMDS metadata.

### Configuration

Enable and tune the cache with the following environment variables (documented in [configuration.md](./configuration.md)):

- `NIMBUS_NEAR_CACHE_ENABLE`, `NIMBUS_NEAR_CACHE_DIR`, `NIMBUS_NEAR_CACHE_BIND`, `NIMBUS_NEAR_CACHE_ADVERTISE`
- Optional port range and S3 parameters: `NIMBUS_NEAR_CACHE_PORT`, `NIMBUS_NEAR_CACHE_PORT_START`, `NIMBUS_NEAR_CACHE_PORT_END`, `NIMBUS_NEAR_CACHE_S3_*`
- Guest mount controls: `NIMBUS_NEAR_CACHE_MOUNT_TAG`, `NIMBUS_NEAR_CACHE_MOUNT_PATH`, `NIMBUS_NEAR_CACHE_VIRTIOFSD`

**Operational checklist**

- Ensure the cache directory resides on SSD/NVMe media for best performance.
- Package `virtiofsd` with your host image when expecting guest mounts.
- Configure IAM permissions for the S3 bucket when write-through is enabled.

## SSH Debugging Sessions

The control plane exposes a token-gated SSH workflow for live troubleshooting of Firecracker guests.

### Flow

1. An admin calls `POST /api/ssh/sessions` with the target job ID.
2. The control plane mints an HMAC token (`NIMBUS_SSH_SESSION_SECRET`) and reserves a host port.
3. The host agent polls `GET /api/agents/ssh/sessions` and, once a session is assigned, configures DNAT rules using the reserved port.
4. When the microVM reports its guest IP, the agent activates the session via `POST /api/ssh/sessions/{id}/activate`.
5. The CLI (or user) connects through the gateway using the Bearer token. Closing the session or TTL expiry revokes the token server-side.

### Required settings

- Control plane: `NIMBUS_SSH_SESSION_SECRET`, `NIMBUS_SSH_PORT_START`, `NIMBUS_SSH_PORT_END`, `NIMBUS_SSH_SESSION_TTL`
- Host agent: `NIMBUS_SSH_ENABLE`, `NIMBUS_SSH_POLL_INTERVAL`, and `NIMBUS_SSH_AUTHORIZED_KEY`

**Operational tips**

- Rotate `NIMBUS_SSH_SESSION_SECRET` alongside other control-plane secrets.
- Port ranges should avoid conflicts with existing ingress rules.
- Agents automatically purge expired sessions; monitor the `Expired SSH sessions cleaned up` log line for drift.

## Prebuilt Runner Images

Nimbus ships with curated base images that mimic common GitHub runner stacks while incorporating platform hardening.

### Registry

The `nimbus.runners.images` module tracks canonical aliases. Current mappings:

| Alias | Image reference |
| --- | --- |
| `ubuntu-2404` | `nimbus/ubuntu-2404-runner:latest` |
| `ubuntu-2204` | `nimbus/ubuntu-2204-runner:latest` |
| `node-22` | `nimbus/node-22-runner:latest` |
| `python-312` | `nimbus/python-312-runner:latest` |

### Consumption patterns

- Jobs can opt in with a label: `image:ubuntu-2204` or `image:python-312`.
- Without explicit labels, the Docker executor maps generic tags (e.g. `node`, `python`) to the maintained images.
- The control plane exposes `GET /api/runners/images` for UI and tooling to discover available aliases.

**Operational tips**

- Keep the image repository mirrored in your private registry if outbound pulls are restricted.
- Use scheduled CI to validate language runtimes and security updates within these images.

## Hardware-Aware Scheduling

Host agents now include a hardware snapshot with every lease request. The control plane uses these metrics to respect job requirements expressed as labels.

### Metrics collected

- CPU core count and average MHz (via `/proc/cpuinfo`)
- Total memory in MB (from `/proc/meminfo`)
- NVMe presence (`/sys/block/nvme*` probe)

### Supported labels

| Label | Requirement |
| --- | --- |
| `cpu-high` | Host must report ≥ 8 cores |
| `cpu-medium` | Host must report ≥ 4 cores |
| `memory-high` | Host must report ≥ 32 GB RAM |
| `storage-nvme` | Host must expose NVMe storage |

### Workflow

- Agents attach `hardware` metrics to `JobLeaseRequest`.
- The control plane quick-scans the Redis queue, skipping jobs whose labels are not satisfied by the requesting host.
- When no capable host is available the job remains queued, preserving order.

**Operational tips**

- Align autoscaling groups with these profiles (e.g. dedicated NVMe group) and spread agent IDs accordingly.
- Expose additional metrics in `_hardware_snapshot()` if new labels are introduced.

## Self-Service Analytics

Nimbus now surfaces near-real-time execution insights through a programmatic API and the web dashboard.

### Control plane API

- `GET /api/analytics/jobs?days=<n>&org_id=<id>` returns daily buckets of job outcomes, filtered per organization when requested.
- Each bucket contains a `date`, `total`, and per-status counts.
- Authentication uses the existing admin bearer token scheme.

### Dashboard page

- The web UI includes an **Analytics** tab that queries the API when a control-plane base URL and admin token are configured in settings.
- Users can review rolling success/failure totals and identify regressions without leaving the dashboard.

**Operational tips**

- Use the API to feed downstream BI tools or to trigger alerts on failure spikes.
- Front-end fetch retries follow standard `fetch` semantics; configure a CDN or cache if latency becomes an issue.

---

For deployment runbooks and additional operational context, consult [operations.md](./operations.md) and [EXECUTOR_SYSTEM.md](./EXECUTOR_SYSTEM.md).
