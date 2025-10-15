"""CLI entrypoint for the rootfs build pipeline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from .config import RootfsPipelineConfig
from .pipeline import RootfsPipeline


def load_config(path: Path) -> RootfsPipelineConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if "rootfs" in data and isinstance(data["rootfs"], dict):
        data = data["rootfs"]
    return RootfsPipelineConfig.model_validate(data)


def build_command(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    if args.set_default:
        config = config.model_copy(update={"default_version": args.set_default})
    pipeline = RootfsPipeline(config)
    pipeline.build(target_version=args.version)
    if args.set_default:
        pipeline.activate(args.set_default)
    return 0


def activate_command(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    pipeline = RootfsPipeline(config)
    pipeline.activate(args.version)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage Firecracker rootfs images")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build rootfs versions from configuration")
    build_parser.add_argument("--config", required=True, help="Path to pipeline YAML configuration")
    build_parser.add_argument("--version", help="Build only the named version")
    build_parser.add_argument(
        "--set-default",
        help="Set the provided version as default after building",
    )

    activate_parser = subparsers.add_parser("activate", help="Switch the active rootfs version")
    activate_parser.add_argument("--config", required=True, help="Path to pipeline YAML configuration")
    activate_parser.add_argument("version", help="Version name to activate")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command == "build":
        return build_command(args)
    if args.command == "activate":
        return activate_command(args)
    raise ValueError(f"unknown command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
