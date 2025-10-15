"""Resource reaper for cleaning up orphaned VMs, tap devices, and network bridges."""

from __future__ import annotations

import asyncio
import re
from typing import Optional

import structlog

LOGGER = structlog.get_logger("nimbus.host_agent.reaper")


async def reap_stale_resources(tap_prefix: str = "nimbus") -> dict[str, int]:
    """
    Scan for and clean up stale Firecracker resources on agent startup.
    
    Returns counts of cleaned resources.
    """
    LOGGER.info("Starting resource reaper", tap_prefix=tap_prefix)
    
    stats = {
        "taps_deleted": 0,
        "bridges_deleted": 0,
        "processes_killed": 0,
    }
    
    # Find stale tap devices
    stale_taps = await _find_stale_taps(tap_prefix)
    LOGGER.info("Found stale tap devices", count=len(stale_taps), taps=stale_taps)
    
    for tap in stale_taps:
        bridge = f"{tap}-br"
        # Try to clean up bridge first
        if await _delete_bridge(bridge):
            stats["bridges_deleted"] += 1
        # Then clean up tap
        if await _delete_tap(tap):
            stats["taps_deleted"] += 1
    
    # Find and kill stale Firecracker processes
    stale_pids = await _find_stale_firecracker_processes()
    LOGGER.info("Found stale Firecracker processes", count=len(stale_pids))
    
    for pid in stale_pids:
        if await _kill_process(pid):
            stats["processes_killed"] += 1
    
    LOGGER.info("Resource reaper completed", stats=stats)
    return stats


async def _find_stale_taps(prefix: str) -> list[str]:
    """Find tap devices matching the prefix."""
    try:
        process = await asyncio.create_subprocess_exec(
            "ip", "tuntap", "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        
        if process.returncode != 0:
            return []
        
        # Parse output like: "nimbus0000: tap"
        taps = []
        for line in stdout.decode().strip().split("\n"):
            if not line:
                continue
            match = re.match(rf"({prefix}\d+):\s+tap", line)
            if match:
                taps.append(match.group(1))
        
        return taps
    except FileNotFoundError:
        LOGGER.warning("ip command not found, skipping tap cleanup")
        return []
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to list tap devices", error=str(exc))
        return []


async def _delete_tap(tap_name: str) -> bool:
    """Delete a tap device."""
    try:
        process = await asyncio.create_subprocess_exec(
            "ip", "tuntap", "del", "mode", "tap", tap_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        success = process.returncode == 0
        if success:
            LOGGER.debug("Deleted tap device", tap=tap_name)
        return success
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to delete tap device", tap=tap_name, error=str(exc))
        return False


async def _delete_bridge(bridge_name: str) -> bool:
    """Delete a bridge device."""
    try:
        # First try to bring it down
        await asyncio.create_subprocess_exec(
            "ip", "link", "set", bridge_name, "down",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        # Then delete it
        process = await asyncio.create_subprocess_exec(
            "ip", "link", "del", bridge_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        success = process.returncode == 0
        if success:
            LOGGER.debug("Deleted bridge", bridge=bridge_name)
        return success
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("Failed to delete bridge", bridge=bridge_name, error=str(exc))
        return False


async def _find_stale_firecracker_processes() -> list[int]:
    """Find Firecracker processes that might be orphaned."""
    try:
        process = await asyncio.create_subprocess_exec(
            "pgrep", "-f", "firecracker",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        
        if process.returncode != 0:
            return []
        
        pids = []
        for line in stdout.decode().strip().split("\n"):
            if line.strip():
                try:
                    pids.append(int(line.strip()))
                except ValueError:
                    pass
        
        return pids
    except FileNotFoundError:
        LOGGER.debug("pgrep not found, skipping process cleanup")
        return []
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to find Firecracker processes", error=str(exc))
        return []


async def _kill_process(pid: int) -> bool:
    """Kill a process by PID."""
    try:
        # Send SIGTERM first
        process = await asyncio.create_subprocess_exec(
            "kill", str(pid),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        
        if process.returncode == 0:
            LOGGER.debug("Killed Firecracker process", pid=pid)
            return True
        return False
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Failed to kill process", pid=pid, error=str(exc))
        return False


async def teardown_job_resources(
    job_id: int,
    tap_prefix: str,
    *,
    vm_process: Optional[asyncio.subprocess.Process] = None,
) -> None:
    """
    Idempotent teardown of all resources for a job.
    Safe to call multiple times.
    """
    tap_name = f"{tap_prefix}{job_id % 10000:04d}"
    bridge_name = f"{tap_name}-br"
    
    LOGGER.info("Tearing down job resources", job_id=job_id, tap=tap_name, bridge=bridge_name)
    
    # Kill VM process if provided
    if vm_process and vm_process.returncode is None:
        try:
            vm_process.terminate()
            try:
                await asyncio.wait_for(vm_process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                vm_process.kill()
                await vm_process.wait()
            LOGGER.debug("VM process terminated", job_id=job_id)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to terminate VM process", job_id=job_id, error=str(exc))
    
    # Clean up network resources (idempotent - ignore errors)
    await _delete_bridge(bridge_name)
    await _delete_tap(tap_name)
    
    LOGGER.info("Job resource teardown complete", job_id=job_id)
