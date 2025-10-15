from __future__ import annotations

import json
from pathlib import Path

import yaml

from smith.rootfs.cli import main as rootfs_cli_main
from smith.rootfs.config import RootfsPipelineConfig, RootfsVersionConfig
from smith.rootfs.pipeline import RootfsPipeline


def _write_dummy_rootfs(path: Path, content: str) -> None:
    path.write_bytes(content.encode("utf-8"))


def test_pipeline_builds_versions_and_updates_manifest(tmp_path: Path) -> None:
    base_v1 = tmp_path / "base-v1.ext4"
    base_v2 = tmp_path / "base-v2.ext4"
    _write_dummy_rootfs(base_v1, "v1")
    _write_dummy_rootfs(base_v2, "v2")

    overlay_dir = tmp_path / "overlay"
    (overlay_dir / "etc").mkdir(parents=True)
    (overlay_dir / "etc" / "config.json").write_text("{}", encoding="utf-8")

    config = RootfsPipelineConfig(
        output_dir=tmp_path / "artifacts",
        default_version="dev",
        versions=[
            RootfsVersionConfig(
                name="dev",
                base_path=base_v1,
                overlay_dir=overlay_dir,
                description="dev image",
            ),
            RootfsVersionConfig(
                name="ci",
                base_path=base_v2,
                description="ci image",
            ),
        ],
    )

    pipeline = RootfsPipeline(config)
    pipeline.build()

    manifest_path = config.resolved_manifest_path()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(manifest["versions"].keys()) == {"dev", "ci"}
    assert manifest["default_version"] == "dev"

    dev_overlay = config.output_dir / "versions" / "dev" / "overlay" / "etc" / "config.json"
    assert dev_overlay.exists()

    pipeline.activate("ci")
    manifest_after = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_after["default_version"] == "ci"
    current_link = config.output_dir / "current"
    assert current_link.is_symlink()
    assert current_link.resolve() == config.output_dir / "versions" / "ci"


def test_cli_build_single_version(tmp_path: Path) -> None:
    base_v1 = tmp_path / "base-v1.ext4"
    _write_dummy_rootfs(base_v1, "v1")

    config_data = {
        "output_dir": str(tmp_path / "artifacts"),
        "versions": [
            {
                "name": "dev",
                "base_path": str(base_v1),
            },
        ],
    }
    config_path = tmp_path / "rootfs.yaml"
    config_path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    exit_code = rootfs_cli_main(["build", "--config", str(config_path), "--set-default", "dev"])
    assert exit_code == 0

    manifest_path = Path(config_data["output_dir"]) / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["default_version"] == "dev"
    assert set(manifest["versions"].keys()) == {"dev"}
