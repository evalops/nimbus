"""Rootfs build pipeline utilities."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .config import RootfsPipelineConfig, RootfsVersionConfig


class RootfsPipeline:
    def __init__(self, config: RootfsPipelineConfig) -> None:
        self.config = config
        self.base_dir = config.output_dir
        self.versions_dir = self.base_dir / "versions"
        self.downloads_dir = self.base_dir / "downloads"

    def build(self, target_version: str | None = None) -> None:
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self.downloads_dir.mkdir(parents=True, exist_ok=True)

        versions = (
            [self._get_version(target_version)] if target_version else self.config.versions
        )

        manifest = self._load_manifest()
        version_checksums: dict[str, str] = {}

        for version_cfg in versions:
            checksum = self._build_version(version_cfg)
            version_checksums[version_cfg.name] = checksum
            manifest_entry = {
                "name": version_cfg.name,
                "description": version_cfg.description,
                "rootfs_path": str(self._version_rootfs_path(version_cfg.name).relative_to(self.base_dir)),
                "checksum_sha256": checksum,
            }
            overlay_path = self._version_overlay_path(version_cfg.name)
            if overlay_path.exists():
                manifest_entry["overlay_path"] = str(overlay_path.relative_to(self.base_dir))
            if version_cfg.base_url:
                manifest_entry["source"] = {"url": str(version_cfg.base_url)}
            else:
                manifest_entry["source"] = {"path": str(Path(version_cfg.base_path).resolve())}  # type: ignore[arg-type]
            manifest["versions"][version_cfg.name] = manifest_entry

        self._write_manifest(manifest, updated_versions=version_checksums)

    def activate(self, version_name: str) -> None:
        manifest = self._load_manifest()
        if version_name not in manifest["versions"]:
            raise ValueError(f"unknown rootfs version: {version_name}")
        manifest["default_version"] = version_name
        self._write_manifest(manifest)

    def _get_version(self, name: str | None) -> RootfsVersionConfig:
        if not name:
            raise ValueError("version name required")
        for version in self.config.versions:
            if version.name == name:
                return version
        raise ValueError(f"version '{name}' not defined in configuration")

    def _build_version(self, version_cfg: RootfsVersionConfig) -> str:
        version_dir = self.versions_dir / version_cfg.name
        if version_dir.exists():
            shutil.rmtree(version_dir)
        version_dir.mkdir(parents=True, exist_ok=True)

        rootfs_path = version_dir / "rootfs.ext4"
        if version_cfg.base_path:
            shutil.copy2(version_cfg.base_path, rootfs_path)
        else:
            assert version_cfg.base_url is not None
            download_target = self.downloads_dir / Path(version_cfg.base_url.path).name
            if not download_target.exists():
                self._download_file(str(version_cfg.base_url), download_target)
            shutil.copy2(download_target, rootfs_path)

        checksum = self._compute_checksum(rootfs_path)
        if version_cfg.checksum_sha256 and checksum != version_cfg.checksum_sha256:
            raise ValueError(
                f"checksum mismatch for {version_cfg.name}: expected {version_cfg.checksum_sha256}, got {checksum}"
            )

        if version_cfg.overlay_dir:
            overlay_src = Path(version_cfg.overlay_dir)
            if overlay_src.exists():
                shutil.copytree(overlay_src, version_dir / "overlay", dirs_exist_ok=True)

        metadata = {
            "name": version_cfg.name,
            "checksum_sha256": checksum,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "description": version_cfg.description,
        }
        if version_cfg.base_url:
            metadata["source"] = {"url": str(version_cfg.base_url)}
        else:
            metadata["source"] = {"path": str(Path(version_cfg.base_path).resolve())}  # type: ignore[arg-type]
        if version_cfg.overlay_dir:
            metadata["overlay_dir"] = str(Path(version_cfg.overlay_dir).resolve())

        (version_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return checksum

    def _download_file(self, url: str, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with httpx.Client(follow_redirects=True) as client:
            with client.stream("GET", url, timeout=60) as response:
                response.raise_for_status()
                with destination.open("wb") as file_obj:
                    for chunk in response.iter_bytes(1024 * 1024):
                        if chunk:
                            file_obj.write(chunk)

    def _write_manifest(self, manifest: dict[str, Any], updated_versions: dict[str, str] | None = None) -> None:
        manifest.setdefault("versions", {})
        manifest["generated_at"] = datetime.now(timezone.utc).isoformat()
        if self.config.default_version:
            if updated_versions is not None or "default_version" not in manifest:
                manifest["default_version"] = self.config.default_version
        elif "default_version" not in manifest:
            if manifest["versions"]:
                manifest["default_version"] = next(iter(manifest["versions"].keys()))

        manifest_path = self.config.resolved_manifest_path()
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        default_version = manifest.get("default_version")
        if default_version:
            current_link = self.base_dir / "current"
            target = self.versions_dir / default_version
            if current_link.exists() or current_link.is_symlink():
                current_link.unlink()
            current_link.symlink_to(target)

    def _load_manifest(self) -> dict[str, Any]:
        manifest_path = self.config.resolved_manifest_path()
        if manifest_path.exists():
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        return {"versions": {}}

    def _compute_checksum(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _version_rootfs_path(self, version_name: str) -> Path:
        return self.versions_dir / version_name / "rootfs.ext4"

    def _version_overlay_path(self, version_name: str) -> Path:
        return self.versions_dir / version_name / "overlay"
