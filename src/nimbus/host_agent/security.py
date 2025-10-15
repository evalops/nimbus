"""Security utilities for the host agent."""

from __future__ import annotations

import os
import structlog

LOGGER = structlog.get_logger("nimbus.host_agent.security")


def check_capabilities() -> None:
    """
    Check and log current process capabilities.
    Warn if running with excessive privileges.
    """
    try:
        # Check if running as root
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            LOGGER.warning(
                "Running as root without capability dropping - NOT RECOMMENDED",
                uid=os.geteuid(),
                recommendation="Use privileged-setup.sh to drop to CAP_NET_ADMIN only",
            )
            return
        
        # Try to import prctl to check capabilities
        try:
            import prctl
            
            # Check for CAP_NET_ADMIN
            has_net_admin = prctl.cap_effective.net_admin
            
            # Check for CAP_SYS_ADMIN (should NOT have this)
            has_sys_admin = prctl.cap_effective.sys_admin
            
            if has_sys_admin:
                LOGGER.warning(
                    "Process has CAP_SYS_ADMIN - SECURITY RISK",
                    recommendation="Use privileged-setup.sh to drop unnecessary capabilities",
                )
            
            if not has_net_admin:
                LOGGER.warning(
                    "Process lacks CAP_NET_ADMIN - tap device creation may fail",
                    recommendation="Run with CAP_NET_ADMIN or use privileged helper",
                )
            
            if has_net_admin and not has_sys_admin:
                LOGGER.info("Running with minimal capabilities", caps="CAP_NET_ADMIN only")
                
        except ImportError:
            LOGGER.debug("prctl module not available, skipping capability check")
            
    except Exception as exc:
        LOGGER.debug("Capability check failed", error=str(exc))


def drop_capabilities() -> None:
    """
    Drop all capabilities except CAP_NET_ADMIN.
    
    Requires python-prctl: pip install python-prctl
    
    NOTE: This should only be called if the process is already non-root.
    For production, use privileged-setup.sh instead.
    """
    try:
        import prctl
        
        LOGGER.info("Dropping capabilities to CAP_NET_ADMIN only")
        
        # Keep only NET_ADMIN
        prctl.cap_permitted.limit(prctl.CAP_NET_ADMIN)
        prctl.cap_effective.limit(prctl.CAP_NET_ADMIN)
        prctl.cap_inheritable.limit()
        
        LOGGER.info("Capabilities dropped successfully")
        
    except ImportError:
        LOGGER.warning(
            "python-prctl not installed, cannot drop capabilities",
            recommendation="Install with: pip install python-prctl",
        )
    except Exception as exc:
        LOGGER.error("Failed to drop capabilities", error=str(exc))
        raise
