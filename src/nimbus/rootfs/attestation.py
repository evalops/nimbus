"""Rootfs attestation helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import structlog


LOGGER = structlog.get_logger("nimbus.rootfs.attestation")


class RootfsAttestationError(RuntimeError):
    """Raised when rootfs attestation fails."""


@dataclass(slots=True)
class ManifestEntry:
    version: str
    checksum: str
    rootfs_path: Optional[str]

    def resolved_path(self, base_dir: Path) -> Optional[Path]:
        if not self.rootfs_path:
            return None
        return (base_dir / self.rootfs_path).resolve()


class RootfsAttestor:
    """Validates that the configured rootfs matches a trusted manifest."""

    def __init__(
        self,
        manifest_path: Path,
        *,
        required: bool = False,
        version: Optional[str] = None,
    ) -> None:
        self._manifest_path = manifest_path
        self._required = required
        self._requested_version = version
        self._base_dir = manifest_path.parent
        self._entries = self._load_manifest()
        if version and version not in self._entries:
            message = f"Rootfs manifest does not contain requested version '{version}'"
            if required:
                raise RootfsAttestationError(message)
            LOGGER.warning("rootfs_version_missing", version=version, manifest=str(manifest_path))

    def _load_manifest(self) -> dict[str, ManifestEntry]:
        if not self._manifest_path.exists():
            raise RootfsAttestationError(f"Rootfs manifest not found: {self._manifest_path}")
        try:
            payload = json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
            raise RootfsAttestationError(f"Failed to read manifest: {exc}") from exc

        versions = payload.get("versions", {})
        entries: dict[str, ManifestEntry] = {}
        for version, data in versions.items():
            checksum = data.get("checksum_sha256")
            if not isinstance(checksum, str):
                LOGGER.warning("rootfs_manifest_missing_checksum", version=version)
                continue
            entries[version] = ManifestEntry(
                version=version,
                checksum=checksum.lower(),
                rootfs_path=data.get("rootfs_path"),
            )
        if not entries:
            raise RootfsAttestationError("Rootfs manifest did not contain any usable versions")
        return entries

    def verify(self, rootfs_source: Path, checksum: str) -> None:
        checksum = checksum.lower()
        entry = self._select_entry(rootfs_source.resolve())

        if entry is None:
            message = "Rootfs image not listed in manifest"
            if self._required:
                raise RootfsAttestationError(message)
            LOGGER.warning("rootfs_unlisted_in_manifest", path=str(rootfs_source))
            return

        if entry.checksum != checksum:
            raise RootfsAttestationError(
                "Rootfs checksum mismatch (expected %s, got %s)" % (entry.checksum, checksum)
            )

        LOGGER.info(
            "rootfs_attestation_passed",
            version=entry.version,
            checksum=checksum,
            path=str(rootfs_source),
        )

    def _select_entry(self, rootfs_source: Path) -> Optional[ManifestEntry]:
        if self._requested_version:
            entry = self._entries.get(self._requested_version)
            if entry is not None:
                return entry
            return None

        matches: list[ManifestEntry] = []
        for entry in self._entries.values():
            entry_path = entry.resolved_path(self._base_dir)
            if entry_path is None:
                continue
            if entry_path == rootfs_source:
                return entry
            try:
                if entry_path.samefile(rootfs_source):  # type: ignore[attr-defined]
                    matches.append(entry)
            except OSError:
                continue

        if matches:
            if len(matches) > 1:
                LOGGER.warning(
                    "rootfs_multiple_manifest_matches",
                    path=str(rootfs_source),
                    versions=[entry.version for entry in matches],
                )
            return matches[0]

        # Fallback: match by checksum if unique
        checksum_map: dict[str, ManifestEntry] = {}
        for entry in self._entries.values():
            checksum_map.setdefault(entry.checksum, entry)
        return checksum_map.get(next(iter(checksum_map))) if len(checksum_map) == 1 else None
