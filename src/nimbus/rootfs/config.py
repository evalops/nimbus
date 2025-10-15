"""Configuration models for the Firecracker rootfs build pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, model_validator


class RootfsVersionConfig(BaseModel):
    name: str
    base_url: Optional[HttpUrl] = None
    base_path: Optional[Path] = None
    checksum_sha256: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    overlay_dir: Optional[Path] = None
    description: Optional[str] = None

    @model_validator(mode="after")
    def _require_source(cls, values: "RootfsVersionConfig") -> "RootfsVersionConfig":
        if values.base_url is None and values.base_path is None:
            raise ValueError("either base_url or base_path must be provided")
        if values.base_url is not None and values.base_path is not None:
            raise ValueError("provide only one of base_url or base_path")
        return values


class RootfsPipelineConfig(BaseModel):
    output_dir: Path
    manifest_path: Optional[Path] = None
    default_version: Optional[str] = None
    versions: list[RootfsVersionConfig]

    @model_validator(mode="after")
    def _validate_default(cls, values: "RootfsPipelineConfig") -> "RootfsPipelineConfig":
        if values.default_version and values.default_version not in {v.name for v in values.versions}:
            raise ValueError("default_version must reference a defined version")
        return values

    def resolved_manifest_path(self) -> Path:
        if self.manifest_path:
            return self.manifest_path
        return self.output_dir / "manifest.json"
