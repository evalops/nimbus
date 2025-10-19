"""Tests for offline egress enforcement and policy packs."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.nimbus.common.networking import (
    MetadataEndpointDenylist,
    EgressPolicyPack,
    OfflineEgressEnforcer,
)


def _enforcer(*, offline_mode: bool, denylist=None, policy_pack=None, allowed=None) -> OfflineEgressEnforcer:
    deny = MetadataEndpointDenylist(denylist or [])
    pack = policy_pack or EgressPolicyPack([])
    allowed_list = allowed or []
    return OfflineEgressEnforcer(
        offline_mode=offline_mode,
        metadata_denylist=deny,
        policy_pack=pack,
        allowed_registries=allowed_list,
    )


def test_metadata_endpoints_denied():
    enforcer = _enforcer(
        offline_mode=False,
        denylist=["169.254.169.254", "metadata.google.internal"],
    )
    with pytest.raises(PermissionError):
        enforcer.ensure_allowed("http://169.254.169.254/latest/meta-data/iam")

    with pytest.raises(PermissionError):
        enforcer.ensure_allowed("http://metadata.google.internal/computeMetadata/v1/")


def test_policy_pack_default_deny(tmp_path: Path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
policies:
  - effect: allow
    pattern: ^https://allowed\\.example\\.com
""",
        encoding="utf-8",
    )
    pack = EgressPolicyPack.from_file(policy_file)
    enforcer = _enforcer(offline_mode=False, policy_pack=pack)

    # Allowed URL should pass
    enforcer.ensure_allowed("https://allowed.example.com/resource")

    # Anything else should be denied (default deny)
    with pytest.raises(PermissionError):
        enforcer.ensure_allowed("https://forbidden.example.com/")


def test_offline_mode_enforces_allow_list():
    enforcer = _enforcer(
        offline_mode=True,
        allowed=["registry.internal"],
    )

    # Allowed registry passes
    enforcer.ensure_allowed("https://registry.internal/v2/")

    # Other hosts rejected
    with pytest.raises(PermissionError):
        enforcer.ensure_allowed("https://pypi.org/simple")
