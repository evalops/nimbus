from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from nimbus.common.networking import (
    EgressPolicyPack,
    MetadataEndpointDenylist,
    OfflineEgressEnforcer,
    PolicyRule,
)
from nimbus.common.supply_chain import (
    ImagePolicy,
    ensure_provenance,
    generate_spdx_sbom,
)


def test_metadata_denylist_blocks_addresses(monkeypatch):
    denylist = MetadataEndpointDenylist(["169.254.169.254", "metadata.internal"])
    assert denylist.is_blocked("169.254.169.254")

    monkeypatch.setattr("socket.gethostbyname", lambda host: "169.254.169.254")
    assert denylist.is_blocked("metadata.internal")


def test_offline_egress_enforcer_blocks_unapproved_hosts(monkeypatch):
    denylist = MetadataEndpointDenylist(["169.254.169.254"])
    rules = [PolicyRule(pattern=re.compile("^https://registry\\.internal"), effect="allow")]
    pack = EgressPolicyPack(rules)
    enforcer = OfflineEgressEnforcer(
        offline_mode=True,
        metadata_denylist=denylist,
        policy_pack=pack,
        allowed_registries=["registry.internal"],
    )

    enforcer.ensure_allowed("https://registry.internal/model")

    with pytest.raises(PermissionError):
        enforcer.ensure_allowed("https://example.com/data")

    with pytest.raises(PermissionError):
        enforcer.ensure_allowed("http://169.254.169.254/latest")


def test_image_policy_enforces_allow_and_deny_lists(tmp_path: Path, monkeypatch) -> None:
    allow_file = tmp_path / "allow.pub"
    allow_file.write_text("public-key", encoding="utf-8")

    policy = ImagePolicy(allow={"registry.internal/app:stable"}, deny={"bad.registry/app:latest"})
    policy.ensure_allowed("registry.internal/app:stable")

    with pytest.raises(PermissionError):
        policy.ensure_allowed("bad.registry/app:latest")

    called = {}

    def _fake_verify(image_ref: str, *, public_key_path: Path) -> None:
        called["image"] = image_ref
        assert public_key_path == allow_file

    monkeypatch.setattr("nimbus.common.supply_chain.verify_cosign_signature", _fake_verify)

    ensure_provenance(
        "registry.internal/app:stable",
        policy,
        public_key_path=allow_file,
        require_provenance=True,
    )
    assert called["image"] == "registry.internal/app:stable"


def test_generate_spdx_sbom(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    root.mkdir()
    binary = root / "bin"
    binary.write_bytes(b"payload")

    destination = tmp_path / "sbom.json"
    generate_spdx_sbom(root, destination)

    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["name"] == "Nimbus SBOM"
    assert data["files"][0]["fileName"] == "bin"
