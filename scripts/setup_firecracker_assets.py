#!/usr/bin/env python3
"""Download kernel and rootfs artifacts for Smith Firecracker hosts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx


DEFAULT_KERNEL_URL = (
    "https://github.com/firecracker-microvm/firecracker/releases/download/"
    "v1.5.0/vmlinux-5.10"
)
DEFAULT_ROOTFS_URL = (
    "https://github.com/actions/runner-images/releases/download/"
    "ubuntu22/ubuntu-22.04-x86_64-rootfs.ext4"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="Directory to store downloaded assets")
    parser.add_argument(
        "--kernel-url",
        default=DEFAULT_KERNEL_URL,
        help="URL of the Firecracker-compatible kernel image",
    )
    parser.add_argument(
        "--rootfs-url",
        default=DEFAULT_ROOTFS_URL,
        help="URL of the root filesystem image",
    )
    return parser.parse_args()


def download_file(client: httpx.Client, url: str, destination: Path) -> None:
    with client.stream("GET", url, timeout=60) as response:
        response.raise_for_status()
        with destination.open("wb") as file_obj:
            for chunk in response.iter_bytes(1024 * 1024):
                if chunk:
                    file_obj.write(chunk)


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    kernel_path = args.output_dir / Path(args.kernel_url).name
    rootfs_path = args.output_dir / Path(args.rootfs_url).name

    with httpx.Client() as client:
        download_file(client, args.kernel_url, kernel_path)
        download_file(client, args.rootfs_url, rootfs_path)

    print(f"Kernel saved to {kernel_path}")
    print(f"Rootfs saved to {rootfs_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
