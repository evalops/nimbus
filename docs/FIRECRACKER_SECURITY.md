# Firecracker Security Hardening

## Overview

This document describes the security hardening measures for Firecracker VMs in Nimbus, including jailer configuration, seccomp profiles, and capability dropping.

## Current State

✅ **Jailer enforced by default** – `FirecrackerLauncher` launches microVMs through the jailer whenever `NIMBUS_JAILER_BIN` is configured, staging a dedicated chroot per VM (see `src/nimbus/host_agent/firecracker.py::_spawn_firecracker_with_jailer`).

✅ **Seccomp filter support** – Architecture-aware seccomp profiles can be supplied via `NIMBUS_SECCOMP_FILTER`; the launcher automatically passes the filter to the jailer and warns if the file is missing.

✅ **Capability minimisation** – The host agent refuses to run as root and drops to `CAP_NET_ADMIN` only (`src/nimbus/host_agent/security.py`). Helper scripts in `scripts/` set up privileged networking before capabilities are reduced.

✅ **Per-VM network namespaces** – Each launcher invocation now provisions an isolated netns, attaches a veth bridge pair, and runs the jailer with `--netns` (see `_setup_network_namespace`). Cleanup removes both the namespace and link scaffolding.

✅ **Read-only rootfs with deterministic rate limits** – Staged rootfs images are chmodded read-only and Firecracker is configured with `ro` kernel args plus RX/TX bandwidth shapers derived from `NIMBUS_NET_*` settings, further constraining guest impact on the host.

## Required Security Measures

### 1. Firecracker Jailer

The jailer creates a minimal, isolated environment for the Firecracker process:

#### Benefits
- **Process isolation**: Runs in a new PID namespace
- **Filesystem isolation**: Chroot into minimal directory
- **Resource limits**: cgroup-based resource constraints
- **Privilege dropping**: Drops to non-root user after setup

#### Configuration

```python
# In HostAgentSettings
jailer_bin_path: str = "/usr/local/bin/jailer"
jailer_uid: int = 1000  # Non-root UID to drop to
jailer_gid: int = 1000  # Non-root GID
jailer_chroot_base: Path = Path("/srv/jailer")
```

#### Usage

```bash
jailer \
  --id <unique-id> \
  --exec-file /usr/local/bin/firecracker \
  --uid 1000 \
  --gid 1000 \
  --chroot-base-dir /srv/jailer \
  --netns <netns-path> \
  --daemonize \
  -- \
  --api-sock /run/firecracker.sock \
  --log-path /run/firecracker.log
```

### 2. Seccomp Profile

Seccomp filters restrict which syscalls Firecracker can make.

#### Architecture-Specific Profiles

**CRITICAL**: Use the correct seccomp profile for your host architecture. Firecracker provides separate profiles for VMM and API threads.

**x86_64:**
```bash
# Download architecture-specific profile
curl -o /etc/nimbus/seccomp-x86_64.json \
  https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/seccomp/x86_64-unknown-linux-musl.json
```

**aarch64 (ARM64):**
```bash
# Download ARM64-specific profile
curl -o /etc/nimbus/seccomp-aarch64.json \
  https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/seccomp/aarch64-unknown-linux-musl.json
```

#### Detect Architecture and Apply

```python
import platform

def get_seccomp_profile_path() -> Path:
    """Get architecture-specific seccomp profile."""
    arch = platform.machine()
    if arch == "x86_64":
        return Path("/etc/nimbus/seccomp-x86_64.json")
    elif arch == "aarch64":
        return Path("/etc/nimbus/seccomp-aarch64.json")
    else:
        raise RuntimeError(f"Unsupported architecture: {arch}")
```

#### Update Policy

**IMPORTANT**: Seccomp profiles must be updated when upgrading Firecracker. The allowed syscalls list changes between versions.

```bash
# Add to deployment/upgrade scripts
FIRECRACKER_VERSION="v1.7.0"
curl -o /etc/nimbus/seccomp-$(uname -m).json \
  https://raw.githubusercontent.com/firecracker-microvm/firecracker/${FIRECRACKER_VERSION}/resources/seccomp/$(uname -m)-unknown-linux-musl.json
```

#### Apply in Jailer

```bash
jailer \
  --seccomp-filter /etc/nimbus/seccomp-$(uname -m).json \
  # ... other args
```

### 3. Host Agent Capabilities

Drop unnecessary Linux capabilities from the host agent process.

#### Minimize CAP_SYS_ADMIN

**WARNING**: `CAP_SYS_ADMIN` is extremely broad ("the new root") and should be avoided.

**Recommended approach**: Use a privileged helper for setup, then drop to minimal capabilities.

```bash
#!/bin/bash
# nimbus-privileged-setup.sh - Run once at agent startup as root

set -euo pipefail

AGENT_USER=${NIMBUS_AGENT_USER:-nimbus}
AGENT_GROUP=${NIMBUS_AGENT_GROUP:-$AGENT_USER}
NET_SETUP_SCRIPT=${NIMBUS_AGENT_NETWORK_SETUP_SCRIPT:-}

if [[ -n "${NET_SETUP_SCRIPT}" ]]; then
  "${NET_SETUP_SCRIPT}"
fi

if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --create-home "${AGENT_USER}"
fi

exec setpriv \
  --reuid="${AGENT_USER}" \
  --regid="${AGENT_GROUP}" \
  --init-groups \
  --no-new-privs \
  --inh-caps=cap_net_admin \
  --ambient-caps=cap_net_admin \
  --bounding-set=cap_net_admin \
  "$@"
```

#### Required Capabilities (Minimal Set)
- `CAP_NET_ADMIN` - Create tap devices and bridges, manage network namespaces
- ~~`CAP_SYS_ADMIN`~~ - **NOT NEEDED** if setup is done by privileged helper

#### Drop All Others

```python
import prctl  # pip install python-prctl

def drop_capabilities():
    """Drop all capabilities except NET_ADMIN."""
    import prctl
    
    # Keep only NET_ADMIN
    prctl.cap_permitted.limit(prctl.CAP_NET_ADMIN)
    prctl.cap_effective.limit(prctl.CAP_NET_ADMIN)
    prctl.cap_inheritable.limit()
```

#### Production Pattern: Privileged Helper + Capability Drop

```bash
# 1. Optional network prep script (creates tap templates, bridges, etc.)
ExecStartPre=/usr/local/bin/nimbus-network-setup.sh
# 2. Main process enters capability-restricted wrapper
ExecStart=/usr/local/bin/nimbus-privileged-setup.sh /usr/bin/python -m nimbus.host_agent.main
```

### 4. Network Namespace Per VM

The launcher now provisions a dedicated namespace for every job via `_setup_network_namespace`, using `pyroute2` to create veth pairs (`tap-hv`/`tap-nv`), an in-namespace bridge, and a jailed tap. The jailer is invoked with `--netns /var/run/netns/<tap-name>-ns`, ensuring Firecracker never shares a network namespace with other workloads.

### 5. Tap Device Naming with Unique IDs

Prevent tap name collisions by using UUIDs or random suffixes.

```python
def allocate_tap_name(self, job_id: int) -> str:
    """Generate unique tap name with random suffix."""
    import secrets
    suffix = secrets.token_hex(4)
    return f"nimbus-{job_id}-{suffix}"
```

## Advanced Security Considerations

### 1. PID Namespace Isolation

Use `--new-pid-ns` to create a new PID namespace for Firecracker.

**Benefits:**
- Firecracker becomes PID 1 inside the namespace
- Hides host PIDs from the guest
- Reduces PID-based attack surface

```bash
jailer \
  --new-pid-ns \
  # ... other args
```

### 2. Read-Only Rootfs

Nimbus stages a per-job copy of the rootfs, marks it read-only, and appends `ro` to the Firecracker kernel args before launch. Operators can use the checks below to verify guest expectations when auditing environments.

```bash
# In Firecracker boot args
kernel_args: "console=ttyS0 reboot=k panic=1 pci=off ro"
```

**Checklist:**
- [x] Rootfs mounted read-only
- [ ] No setuid/setgid binaries in chroot
- [ ] Minimal binaries in chroot (only Firecracker)
- [ ] No shared memory access from chroot

### 3. Device Model Minimization

Firecracker's security design minimizes exposed device surface.

**Enabled by default:**
- ✅ VirtIO Block (disk)
- ✅ VirtIO Net (network)
- ✅ RX/TX rate limiters (token-bucket per `NIMBUS_NET_*` settings)

**Disable unless required:**
- ❌ vsock (adds syscalls to seccomp profile)
- ❌ Snapshot/restore (increases complexity)

**If vsock is required:**
- Use updated seccomp profile that includes vsock syscalls
- Restrict guest access to host services
- Document security implications

### 4. Logging Outside Chroot

**CRITICAL**: Logs must be collected outside the chroot to prevent tampering.

```python
# Mount named pipes into chroot for log collection
log_pipe_host = Path("/var/run/nimbus/logs/{vm_id}.pipe")
log_pipe_chroot = jailer_chroot / "run/firecracker.log"

# Create pipe outside chroot
os.mkfifo(log_pipe_host)

# Bind-mount into chroot (or use jailer's --parent-cgroup with logging)
```

**Do NOT:**
- Write logs inside the chroot
- Allow guest write access to log files
- Expose sensitive guest data in host logs

### 5. Update Policy

**CRITICAL**: Keep Firecracker and kernel updated for security patches.

#### Firecracker Updates
```bash
# Check current version
firecracker --version

# Subscribe to security advisories
# https://github.com/firecracker-microvm/firecracker/security/advisories
```

#### Kernel Updates
```bash
# Use latest stable kernel recommended by Firecracker
# Check compatibility: https://github.com/firecracker-microvm/firecracker/blob/main/docs/kernel-policy.md
```

#### Update Procedure
1. Review Firecracker release notes for breaking changes
2. Update seccomp profile to match new version
3. Test in staging with representative workloads
4. Roll out to production with phased deployment
5. Monitor for syscall violations in logs

**Recommended cadence:** Quarterly security updates, immediate patches for CVEs

### 6. Security Monitoring

Monitor for security events:

```bash
# Check for seccomp violations
dmesg | grep -i seccomp

# Monitor syscall violations
ausearch -m SECCOMP -ts recent

# Check jailer logs for privilege escalation attempts
journalctl -u nimbus-agent | grep -i "capability\|setuid\|chroot"
```

**Alert on:**
- Seccomp filter violations
- Unexpected capability usage
- Failed chroot operations
- Firecracker crashes or panics
- Jailer errors

## Implementation Status

### Phase 1: Jailer Integration (P0) – ✅ Complete

- `HostAgentSettings` exposes `NIMBUS_JAILER_*` configuration toggles.
- `FirecrackerLauncher` provisions a per-VM chroot, copies kernel/rootfs assets, and executes Firecracker via the jailer with `--new-pid-ns` for PID isolation.
- Chroot directories are removed automatically after each job.

### Phase 2: Seccomp Profile (P0) – ✅ Complete

- Operators can attach an architecture-appropriate seccomp filter using `NIMBUS_SECCOMP_FILTER`.
- The launcher injects the filter into the jailer command and warns if the configured file is absent, reducing the risk of drift.

### Phase 3: Capability Dropping (P0) – ✅ Complete

- Startup checks in `src/nimbus/host_agent/security.py` prevent root execution and drop all capabilities except `CAP_NET_ADMIN`.
- Helper scripts such as `scripts/nimbus-privileged-setup.sh` run privileged setup (bridge/tap preparation) before control passes to the unprivileged agent.

### Phase 4: Network Namespace Isolation (P1) – ✅ Complete

- Each job now gets an isolated network namespace; the launcher provisions veth pairs, an internal bridge, and passes `--netns` to the jailer.
- Teardown removes namespaces and link scaffolding to prevent leakage between workloads.

### Phase 5: Rootfs Hardening & Rate Limiting (P1) – ✅ Complete

- Rootfs snapshots staged per job are chmodded read-only and Firecracker boot args enforce `ro` to prevent guest writes to the base image.
- RX/TX token-bucket rate limiters are configured through `NIMBUS_NET_*` settings, reducing the blast radius of compromised guests.

## Example Implementation

```python
# In firecracker.py

async def _spawn_firecracker_with_jailer(
    self,
    api_socket: Path,
    log_path: Path,
    metrics_path: Path,
    vm_id: str,
    tap_name: str,
) -> asyncio.subprocess.Process:
    """Spawn Firecracker using the jailer for security isolation."""
    
    jailer_chroot = self._settings.jailer_chroot_base / vm_id
    jailer_chroot.mkdir(parents=True, exist_ok=True)
    
    # Copy/link required files into chroot
    (jailer_chroot / "firecracker").symlink_to(self._settings.firecracker_bin_path)
    
    # Jailer args
    cmd = [
        self._settings.jailer_bin_path,
        "--id", vm_id,
        "--exec-file", "/firecracker",
        "--uid", str(self._settings.jailer_uid),
        "--gid", str(self._settings.jailer_gid),
        "--chroot-base-dir", str(self._settings.jailer_chroot_base),
    ]
    
    if self._settings.seccomp_filter_path:
        cmd.extend(["--seccomp-filter", str(self._settings.seccomp_filter_path)])
    
    # Firecracker args (after --)
    cmd.extend([
        "--",
        "--api-sock", str(api_socket),
        "--log-path", str(log_path),
        "--level", "Info",
        "--metrics-path", str(metrics_path),
    ])
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    await asyncio.sleep(0.2)  # Allow jailer to set up
    
    if process.returncode is not None:
        stdout, stderr = await process.communicate()
        raise FirecrackerError(
            f"Jailer/Firecracker exited: {stderr.decode().strip()}"
        )
    
    return process
```

## Testing

### Verify Jailer Isolation

```bash
# Check process namespace
ps aux | grep firecracker
# Should show process running as non-root user

# Check chroot
sudo ls -la /srv/jailer/{vm-id}/root
# Should show minimal filesystem

# Check seccomp
grep Seccomp /proc/{firecracker-pid}/status
# Should show mode 2 (filtering enabled)
```

### Verify Capabilities

```bash
# Check host agent capabilities
getpcaps {agent-pid}
# Should show minimal capabilities
```

## Security Checklist

Before production:

### Jailer Configuration
- [x] Firecracker runs under jailer
- [x] Jailer drops to non-root user (UID > 1000)
- [x] `--new-pid-ns` enabled for PID namespace isolation
- [ ] Architecture-specific seccomp profile applied *(operator-provided via `NIMBUS_SECCOMP_FILTER`)*
- [ ] Seccomp profile version matches Firecracker version *(review during upgrades)*
- [x] Chroot contains only Firecracker binary and staged assets per job
- [x] Chroot directories cleaned up after VM exit

### Capabilities & Permissions
- [x] Host agent runs with CAP_NET_ADMIN only (no CAP_SYS_ADMIN)
- [x] Privileged helper script for initial setup
- [x] No setuid/setgid binaries in chroot staging
- [ ] Rootfs mounted read-only where possible *(optional hardening)*

### Network Isolation
- [ ] Network namespaces per VM *(optional hardening)*
- [x] Tap devices use deterministic per-job names with isolation
- [x] Network bridges configured and cleaned between jobs

### Device Models
- [x] Only VirtIO Block and Net enabled (default)
- [x] vsock disabled unless explicitly required
- [ ] Snapshot/restore disabled in production *(enable only when needed)*
- [ ] Rate limiters configured if needed

### Monitoring & Updates
- [ ] Logs collected outside chroot via named pipes
- [ ] Seccomp violations monitored (dmesg, auditd)
- [ ] Firecracker update policy documented and followed
- [ ] Kernel update policy documented and followed
- [ ] Security advisories monitored
- [ ] Quarterly security update schedule established

### Resource Controls
- [ ] CPU limits enforced via cgroups
- [ ] Memory limits enforced via cgroups
- [ ] I/O limits configured
- [ ] Per-VM resource quotas defined

## Resources

- [Firecracker Jailer Documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
- [Firecracker Security Model](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md#security-model)
- [Seccomp Filter Profile](https://github.com/firecracker-microvm/firecracker/tree/main/resources/seccomp)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
