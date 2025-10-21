"""Supply chain security helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import json
import structlog
from structlog.stdlib import BoundLogger
from sigstore.verify import VerificationMaterials, verifier


LOGGER = structlog.get_logger("nimbus.common.supply_chain")


class ImagePolicy:
    def __init__(self, allow: set[str], deny: set[str]) -> None:
        self._allow = {entry.lower() for entry in allow}
        self._deny = {entry.lower() for entry in deny}

    @classmethod
    def from_paths(cls, allow_path: Optional[Path], deny_path: Optional[Path]) -> "ImagePolicy":
        allow = _load_list_file(allow_path)
        deny = _load_list_file(deny_path)
        return cls(set(allow), set(deny))

    def ensure_allowed(self, reference: str) -> None:
        normalized = reference.lower()
        if normalized in self._deny:
            raise PermissionError(f"Image {reference} denied by policy")
        if self._allow and normalized not in self._allow:
            raise PermissionError(f"Image {reference} not present in allow list")


def _load_list_file(path: Optional[Path]) -> list[str]:
    if path is None or not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#"):
            lines.append(cleaned)
    return lines


def verify_cosign_signature(
    image_ref: str,
    *,
    public_key_path: Optional[Path],
) -> None:
    if public_key_path is None or not public_key_path.exists():
        raise PermissionError("Cosign public key not configured")
    materials = VerificationMaterials.signed_image(image_ref, public_key=public_key_path.read_text(encoding="utf-8"))
    cosign_verifier = verifier.Verifier()
    cosign_verifier.verify(materials)
    LOGGER.info("Cosign verification succeeded", image=image_ref)


@dataclass(slots=True)
class SLSAOptions:
    """Configuration for SLSA attestation verification."""

    attestation_dir: Path
    allowed_builders: set[str]
    predicate_type: Optional[str] = "https://slsa.dev/provenance/v1"
    require_attestation: bool = False


class SLSAVerifier:
    """Validate SLSA provenance attestations emitted by trusted builders."""

    def __init__(self, options: SLSAOptions) -> None:
        self._options = options

    def verify(self, image_ref: str) -> None:
        attestation_path = self._resolve_attestation_path(image_ref)
        if attestation_path is None:
            if self._options.require_attestation:
                raise PermissionError(f"No SLSA attestation found for {image_ref}")
            LOGGER.debug("slsa_attestation_missing", image=image_ref)
            return

        try:
            raw = attestation_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if self._options.require_attestation:
                raise PermissionError(f"No SLSA attestation found for {image_ref}") from None
            LOGGER.debug("slsa_attestation_missing", image=image_ref)
            return

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PermissionError(f"Invalid SLSA attestation JSON: {exc}") from exc

        predicate_type = payload.get("predicateType")
        if self._options.predicate_type and predicate_type != self._options.predicate_type:
            raise PermissionError(
                f"SLSA predicate type mismatch: expected {self._options.predicate_type}, got {predicate_type}"
            )

        builder_id = (
            payload.get("predicate", {})
            .get("builder", {})
            .get("id")
        )
        if self._options.allowed_builders and builder_id not in self._options.allowed_builders:
            raise PermissionError(f"SLSA builder {builder_id!r} not permitted")

        expected_digest = self._extract_digest(image_ref)
        if expected_digest:
            subjects = payload.get("subject", [])
            if not any(self._digest_matches(subject, expected_digest) for subject in subjects):
                raise PermissionError("SLSA subject digest mismatch")

        LOGGER.info("SLSA verification succeeded", image=image_ref, attestation=str(attestation_path))

    def _resolve_attestation_path(self, image_ref: str) -> Optional[Path]:
        digest = self._extract_digest(image_ref)
        candidates: list[Path] = []
        if digest:
            candidates.append(self._options.attestation_dir / f"{digest}.json")
        candidates.append(self._options.attestation_dir / f"{self._sanitize(image_ref)}.json")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0] if candidates else None

    @staticmethod
    def _sanitize(reference: str) -> str:
        return "".join(char if char.isalnum() else "_" for char in reference)

    @staticmethod
    def _extract_digest(reference: str) -> Optional[str]:
        if "@sha256:" in reference:
            return reference.split("@sha256:", 1)[1]
        return None

    @staticmethod
    def _digest_matches(subject: dict, expected: str) -> bool:
        digest_map = subject.get("digest", {})
        for algorithm, value in digest_map.items():
            if algorithm.lower() == "sha256" and value.lower() == expected.lower():
                return True
        return False


def generate_spdx_sbom(root: Path, destination: Path) -> None:
    file_entries = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        file_entry = {
            "fileName": str(path.relative_to(root)),
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": digest,
                }
            ],
        }
        file_entries.append(file_entry)
    doc_dict = {
        "spdxVersion": "SPDX-2.3",
        "name": "Nimbus SBOM",
        "creationInfo": {
            "creators": ["Tool: NimbusSupplyChain"],
        },
        "files": file_entries,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(doc_dict, indent=2), encoding="utf-8")
    LOGGER.info("SBOM generated", destination=str(destination))


def ensure_provenance(
    image_ref: str,
    policy: ImagePolicy,
    *,
    public_key_path: Optional[Path],
    require_provenance: bool,
    grace_until: Optional[datetime] = None,
    logger: Optional[BoundLogger] = None,
    slsa_verifier: Optional[SLSAVerifier] = None,
) -> None:
    policy.ensure_allowed(image_ref)
    if not require_provenance and not slsa_verifier:
        return

    try:
        if require_provenance:
            if not public_key_path or not public_key_path.exists():
                raise PermissionError("cosign key missing")
            if not any(delim in image_ref for delim in (":", "@")):
                raise PermissionError("non-oci reference")
            verify_cosign_signature(image_ref, public_key_path=public_key_path)
        if slsa_verifier:
            slsa_verifier.verify(image_ref)
    except Exception as exc:
        if grace_until and datetime.now(timezone.utc) < grace_until:
            if logger:
                logger.warning(
                    "provenance_grace",
                    image=image_ref,
                    error=str(exc),
                    grace_until=grace_until.isoformat(),
                )
            return
        raise PermissionError(f"Provenance verification failed: {exc}")
