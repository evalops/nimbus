"""Placeholder utilities for optional SSH and DNS features."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class SSHSessionConfig:
    job_id: int
    host_port: int
    vm_ip: str
    authorized_user: str


def configure_ssh_port_forward(config: SSHSessionConfig) -> list[str]:
    """Return iptables commands required to expose a VM over SSH."""

    return [
        f"iptables -t nat -A PREROUTING -p tcp --dport {config.host_port} -j DNAT --to-destination {config.vm_ip}:22",
        f"iptables -A FORWARD -p tcp -d {config.vm_ip} --dport 22 -j ACCEPT",
        f"iptables -t nat -A POSTROUTING -s {config.vm_ip} -p tcp --sport 22 -j MASQUERADE",
    ]


@dataclass
class DNSRegistration:
    hostname: str
    target_ip: str
    ttl: int = 30


def dns_redis_payload(registration: DNSRegistration) -> dict[str, str]:
    """Represent a DNS record suitable for storage in Redis."""

    return {
        "hostname": registration.hostname,
        "target": registration.target_ip,
        "ttl": str(registration.ttl),
    }
