"""Supply chain security helpers."""

from __future__ import annotations

import hashlib
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
) -> None:
    policy.ensure_allowed(image_ref)
    if not require_provenance:
        return

    try:
        if not public_key_path:
            raise PermissionError("cosign key missing")
        if not public_key_path.exists():
            raise PermissionError("cosign key missing")
        if not any(delim in image_ref for delim in (":", "@")):
            raise PermissionError("non-oci reference")
        verify_cosign_signature(image_ref, public_key_path=public_key_path)
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
