# Firecracker Security Hardening

## Overview

This document describes the security hardening measures for Firecracker VMs in Nimbus, including jailer configuration, seccomp profiles, and capability dropping.

## Current State

❌ **Not Implemented** - Firecracker runs without jailer
❌ **Not Implemented** - No seccomp filtering
❌ **Not Implemented** - Host agent runs with full capabilities

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
# privileged-setup.sh - Run once at agent startup as root

# Create tap devices and network namespaces (requires CAP_SYS_ADMIN)
ip netns add nimbus-default
ip tuntap add mode tap nimbus-tap-template

# Drop privileges and exec into agent
exec setpriv \
  --reuid=nimbus \
  --regid=nimbus \
  --init-groups \
  --inh-caps=-all \
  --ambient-caps=cap_net_admin \
  python -m nimbus.host_agent.main
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
# 1. Systemd service runs privileged helper first
ExecStartPre=/usr/local/bin/nimbus-network-setup.sh
# 2. Main process runs with minimal caps
ExecStart=/usr/bin/setpriv --reuid=nimbus --regid=nimbus \
  --inh-caps=-all --ambient-caps=cap_net_admin \
  /usr/bin/python -m nimbus.host_agent.main
```

### 4. Network Namespace Per VM

Isolate VM networking using network namespaces.

```python
async def create_network_namespace(vm_id: str) -> str:
    """Create a dedicated network namespace for a VM."""
    netns_name = f"nimbus-{vm_id}"
    
    # Create namespace
    await asyncio.create_subprocess_exec(
        "ip", "netns", "add", netns_name
    )
    
    # Move tap device into namespace
    await asyncio.create_subprocess_exec(
        "ip", "link", "set", tap_name, "netns", netns_name
    )
    
    return f"/var/run/netns/{netns_name}"
```

Pass to jailer with `--netns /var/run/netns/nimbus-{vm_id}`.

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

Mount rootfs as read-only or with minimal write access.

```bash
# In Firecracker boot args
kernel_args: "console=ttyS0 reboot=k panic=1 pci=off ro"
```

**Checklist:**
- [ ] Rootfs mounted read-only
- [ ] No setuid/setgid binaries in chroot
- [ ] Minimal binaries in chroot (only Firecracker)
- [ ] No shared memory access from chroot

### 3. Device Model Minimization

Firecracker's security design minimizes exposed device surface.

**Enabled by default:**
- ✅ VirtIO Block (disk)
- ✅ VirtIO Net (network)

**Disable unless required:**
- ❌ vsock (adds syscalls to seccomp profile)
- ❌ Snapshot/restore (increases complexity)
- ❌ Rate limiters (only if needed)

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

## Implementation Plan

### Phase 1: Jailer Integration (P0)

1. Add jailer configuration to `HostAgentSettings`
2. Update `FirecrackerLauncher._spawn_firecracker()` to use jailer
3. Prepare chroot directory with required files:
   - Firecracker binary
   - Kernel image
   - Rootfs image (can be bind-mounted)
4. Test VM launch with jailer

### Phase 2: Seccomp Profile (P0)

1. Download and package seccomp profile
2. Add `--seccomp-filter` to jailer invocation
3. Verify Firecracker starts successfully with profile

### Phase 3: Capability Dropping (P0)

1. Add `drop_capabilities()` function to host agent startup
2. Document setcap approach for non-root execution
3. Add capability checks and warnings if running with excess privileges

### Phase 4: Network Namespace Isolation (P1)

1. Create network namespace per VM
2. Move tap device into namespace
3. Pass netns path to jailer
4. Clean up namespace on teardown

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
- [ ] Firecracker runs under jailer
- [ ] Jailer drops to non-root user (UID > 1000)
- [ ] `--new-pid-ns` enabled for PID namespace isolation
- [ ] Architecture-specific seccomp profile applied
- [ ] Seccomp profile version matches Firecracker version
- [ ] Chroot contains only Firecracker binary (no other binaries)
- [ ] Chroot directories cleaned up after VM exit

### Capabilities & Permissions
- [ ] Host agent runs with CAP_NET_ADMIN only (no CAP_SYS_ADMIN)
- [ ] Privileged helper script for initial setup
- [ ] No setuid/setgid binaries in chroot
- [ ] Rootfs mounted read-only where possible

### Network Isolation
- [ ] Network namespaces per VM
- [ ] Tap devices use unique, non-predictable names (UUID-based)
- [ ] Network bridges properly isolated

### Device Models
- [ ] Only VirtIO Block and Net enabled (default)
- [ ] vsock disabled unless explicitly required
- [ ] Snapshot/restore disabled in production
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
