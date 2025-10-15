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

#### Pre-built Profile

Firecracker provides a recommended seccomp profile. Download from:
https://github.com/firecracker-microvm/firecracker/blob/main/resources/seccomp/seccomp-filter.json

```bash
# Download seccomp profile
curl -o /etc/nimbus/seccomp-filter.json \
  https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/seccomp/seccomp-filter.json
```

#### Apply in Jailer

```bash
jailer \
  --seccomp-filter /etc/nimbus/seccomp-filter.json \
  # ... other args
```

### 3. Host Agent Capabilities

Drop unnecessary Linux capabilities from the host agent process.

#### Required Capabilities
- `CAP_NET_ADMIN` - Create tap devices and bridges
- `CAP_SYS_ADMIN` - (Optional, for certain network operations)

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

#### Alternative: Run as Non-Root with Capabilities

```bash
# Set capabilities on agent binary
sudo setcap cap_net_admin=ep /path/to/nimbus-agent

# Run as non-root user
su nimbus -c "python -m nimbus.host_agent.main"
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

- [ ] Firecracker runs under jailer
- [ ] Jailer drops to non-root user (UID > 1000)
- [ ] Seccomp profile applied
- [ ] Host agent runs with minimal capabilities
- [ ] Network namespaces per VM
- [ ] Tap devices use unique, non-predictable names
- [ ] Chroot directories cleaned up after VM exit
- [ ] No suid/sgid binaries in chroot
- [ ] Resource limits (CPU, memory, I/O) enforced via cgroups

## Resources

- [Firecracker Jailer Documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
- [Firecracker Security Model](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md#security-model)
- [Seccomp Filter Profile](https://github.com/firecracker-microvm/firecracker/tree/main/resources/seccomp)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
