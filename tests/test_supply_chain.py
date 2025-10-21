from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
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

    with pytest.raises(PermissionError):
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


def test_ensure_provenance_rejects_non_oci_reference(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("image-without-ref\n", encoding="utf-8")
    key_path = tmp_path / "cosign.pub"
    key_path.write_text("public key", encoding="utf-8")

    policy = supply_chain.ImagePolicy.from_paths(allow, None)

    with pytest.raises(PermissionError):
        supply_chain.ensure_provenance(
            "image-without-ref",
            policy,
            public_key_path=key_path,
            require_provenance=True,
        )


def test_ensure_provenance_grace_period_allows(tmp_path: Path, caplog) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("registry.internal/image:1\n", encoding="utf-8")
    policy = supply_chain.ImagePolicy.from_paths(allow, None)
    grace_until = datetime.now(timezone.utc) + timedelta(days=7)

    supply_chain.ensure_provenance(
        "registry.internal/image:1",
        policy,
        public_key_path=None,
        require_provenance=True,
        grace_until=grace_until,
        logger=supply_chain.LOGGER,
    )


def test_ensure_provenance_grace_expired(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("registry.internal/image:1\n", encoding="utf-8")
    policy = supply_chain.ImagePolicy.from_paths(allow, None)
    grace_until = datetime.now(timezone.utc) - timedelta(seconds=1)

    with pytest.raises(PermissionError):
        supply_chain.ensure_provenance(
            "registry.internal/image:1",
            policy,
            public_key_path=None,
            require_provenance=True,
            grace_until=grace_until,
            logger=supply_chain.LOGGER,
        )


def test_slsa_verifier_accepts_matching_attestation(tmp_path: Path) -> None:
    attestation_dir = tmp_path / "attest"
    attestation_dir.mkdir()
    digest = "a" * 64
    attestation = {
        "subject": [{"name": "registry/image", "digest": {"sha256": digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "builder://trusted"}},
    }
    (attestation_dir / f"{digest}.json").write_text(json.dumps(attestation), encoding="utf-8")
    options = supply_chain.SLSAOptions(attestation_dir=attestation_dir, allowed_builders={"builder://trusted"})
    verifier = supply_chain.SLSAVerifier(options)

    verifier.verify(f"registry/image@sha256:{digest}")


def test_slsa_verifier_rejects_untrusted_builder(tmp_path: Path) -> None:
    attestation_dir = tmp_path / "attest"
    attestation_dir.mkdir()
    digest = "b" * 64
    attestation = {
        "subject": [{"name": "registry/image", "digest": {"sha256": digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "builder://other"}},
    }
    (attestation_dir / f"{digest}.json").write_text(json.dumps(attestation), encoding="utf-8")
    options = supply_chain.SLSAOptions(attestation_dir=attestation_dir, allowed_builders={"builder://trusted"}, require_attestation=True)
    verifier = supply_chain.SLSAVerifier(options)

    with pytest.raises(PermissionError):
        verifier.verify(f"registry/image@sha256:{digest}")


def test_ensure_provenance_enforces_slsa(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    digest = "c" * 64
    allow.write_text(f"registry.internal/image@sha256:{digest}\n", encoding="utf-8")
    policy = supply_chain.ImagePolicy.from_paths(allow, None)
    attestation_dir = tmp_path / "attest"
    attestation_dir.mkdir()
    attestation = {
        "subject": [{"name": "registry.internal/image", "digest": {"sha256": digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "builder://trusted"}},
    }
    (attestation_dir / f"{digest}.json").write_text(json.dumps(attestation), encoding="utf-8")
    options = supply_chain.SLSAOptions(attestation_dir=attestation_dir, allowed_builders={"builder://trusted"}, require_attestation=True)
    verifier = supply_chain.SLSAVerifier(options)

    supply_chain.ensure_provenance(
        f"registry.internal/image@sha256:{digest}",
        policy,
        public_key_path=None,
        require_provenance=False,
        slsa_verifier=verifier,
    )


def test_ensure_provenance_rejects_when_slsa_missing(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("registry.internal/image@sha256:dd\n", encoding="utf-8")
    policy = supply_chain.ImagePolicy.from_paths(allow, None)
    attestation_dir = tmp_path / "attest"
    attestation_dir.mkdir()
    options = supply_chain.SLSAOptions(attestation_dir=attestation_dir, allowed_builders={"builder://trusted"}, require_attestation=True)
    verifier = supply_chain.SLSAVerifier(options)

    with pytest.raises(PermissionError):
        supply_chain.ensure_provenance(
            "registry.internal/image@sha256:dd",
            policy,
            public_key_path=None,
            require_provenance=False,
            slsa_verifier=verifier,
        )
