"""Networking policy utilities for enforcing offline operation and egress controls."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
import ipaddress
import re
import socket
import ssl
import urllib.parse

import yaml


class MetadataEndpointDenylist:
    """Block network access to known metadata endpoints."""

    def __init__(self, entries: Iterable[str] | None = None) -> None:
        self._blocked_hosts: set[str] = set()
        self._blocked_networks: list[ipaddress._BaseNetwork] = []  # type: ignore[attr-defined]
        if not entries:
            return
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                self._blocked_hosts.add(entry.lower())
            else:
                self._blocked_networks.append(network)

    def is_blocked(self, host: str) -> bool:
        normalized = host.lower()
        if normalized in self._blocked_hosts:
            return True
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            try:
                resolved = socket.gethostbyname(host)
            except OSError:
                return False
            return any(ipaddress.ip_address(resolved) in network for network in self._blocked_networks)
        return any(addr in network for network in self._blocked_networks)


@dataclass
class PolicyRule:
    pattern: re.Pattern[str]
    effect: str  # "allow" or "deny"


class EgressPolicyPack:
    """Aggregated allow/deny patterns for outbound requests."""

    def __init__(self, rules: list[PolicyRule]) -> None:
        self._rules = rules

    @classmethod
    def from_file(cls, path: Path | None) -> "EgressPolicyPack":
        if path is None:
            return cls([])
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules: list[PolicyRule] = []
        for item in data.get("policies", []):
            effect = str(item.get("effect", "")).lower()
            pattern = item.get("pattern")
            if effect not in {"allow", "deny"} or not pattern:
                continue
            rules.append(PolicyRule(pattern=re.compile(pattern, re.IGNORECASE), effect=effect))
        return cls(rules)

    def is_allowed(self, target: str) -> bool:
        if not self._rules:
            return True
        for rule in self._rules:
            if rule.pattern.search(target):
                return rule.effect == "allow"
        # default deny when pack is defined
        return False


class OfflineEgressEnforcer:
    """Runtime checker ensuring outbound requests comply with policy and offline mode."""

    def __init__(
        self,
        *,
        offline_mode: bool,
        metadata_denylist: MetadataEndpointDenylist,
        policy_pack: EgressPolicyPack,
        allowed_registries: Iterable[str] | None = None,
    ) -> None:
        self._offline_mode = offline_mode
        self._metadata_denylist = metadata_denylist
        self._policy_pack = policy_pack
        self._allowed_registries = {entry.lower() for entry in allowed_registries or []}

    def ensure_allowed(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname:
            raise PermissionError("Outbound request missing hostname")
        if self._metadata_denylist.is_blocked(hostname):
            raise PermissionError(f"Outbound request to metadata endpoint blocked: {hostname}")
        normalized = f"{parsed.scheme}://{hostname}{parsed.path}"
        if self._policy_pack._rules:
            if not self._policy_pack.is_allowed(normalized):
                raise PermissionError(f"Egress policy denied request to {hostname}")
        if self._offline_mode:
            # Offline mode restricts access to explicit allowed registries
            if hostname.lower() not in self._allowed_registries:
                raise PermissionError(f"Offline mode forbids egress to {hostname}")


def create_guarded_async_client(
    *,
    enforcer: OfflineEgressEnforcer,
    verify: bool = True,
    timeout: Optional[float] = None,
    ca_bundle: Optional[str] = None,
):
    """Provide an httpx.AsyncClient enforcing egress policy on every request."""
    import httpx

    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

    ssl_context: Optional[ssl.SSLContext] = None
    if ca_bundle:
        ssl_context = ssl.create_default_context(cafile=ca_bundle)

    async def _on_request(request: httpx.Request) -> None:
        enforcer.ensure_allowed(str(request.url))

    return httpx.AsyncClient(
        timeout=timeout or 20.0,
        limits=limits,
        verify=verify if ssl_context is None else ssl_context,
        event_hooks={"request": [_on_request]},
    )


def load_allowed_registries(entries: Iterable[str] | None) -> list[str]:
    return sorted({entry.strip().lower() for entry in entries or [] if entry.strip()})
