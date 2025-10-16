from __future__ import annotations

from pathlib import Path

import pytest

from nimbus.common import supply_chain


def test_image_policy_enforces_allow_and_deny(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    deny = tmp_path / "deny.txt"
    allow.write_text("registry.internal/image:1\n", encoding="utf-8")
    deny.write_text("bad.registry/image:latest\n", encoding="utf-8")

    policy = supply_chain.ImagePolicy.from_paths(allow, deny)

    policy.ensure_allowed("registry.internal/image:1")
    with pytest.raises(PermissionError):
        policy.ensure_allowed("bad.registry/image:latest")
    with pytest.raises(PermissionError):
        policy.ensure_allowed("unknown.registry/image:2")


def test_ensure_provenance_skips_when_not_required(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("registry.internal/image:1\n", encoding="utf-8")
    policy = supply_chain.ImagePolicy.from_paths(allow, None)

    # Should not raise even though public key is missing when provenance not required
    supply_chain.ensure_provenance(
        "registry.internal/image:1",
        policy,
        public_key_path=None,
        require_provenance=False,
    )


def test_ensure_provenance_without_key_skips_verification(tmp_path: Path, monkeypatch) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("registry.internal/image:1\n", encoding="utf-8")
    policy = supply_chain.ImagePolicy.from_paths(allow, None)

    def fail_verify(*args, **kwargs):  # noqa: ANN001
        raise AssertionError("verify_cosign_signature should not be called")

    monkeypatch.setattr(supply_chain, "verify_cosign_signature", fail_verify)

    supply_chain.ensure_provenance(
        "registry.internal/image:1",
        policy,
        public_key_path=None,
        require_provenance=True,
    )


def test_ensure_provenance_invokes_cosign(tmp_path: Path, monkeypatch) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("registry.internal/image:1\n", encoding="utf-8")
    key_path = tmp_path / "cosign.pub"
    key_path.write_text("public key", encoding="utf-8")

    policy = supply_chain.ImagePolicy.from_paths(allow, None)

    called: dict[str, bool] = {"invoked": False}

    def fake_verify(image_ref: str, *, public_key_path: Path) -> None:
        called["invoked"] = True
        assert image_ref == "registry.internal/image:1"
        assert public_key_path == key_path

    monkeypatch.setattr(supply_chain, "verify_cosign_signature", fake_verify)

    supply_chain.ensure_provenance(
        "registry.internal/image:1",
        policy,
        public_key_path=key_path,
        require_provenance=True,
    )

    assert called["invoked"] is True
