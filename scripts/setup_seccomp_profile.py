#!/usr/bin/env python3
"""Download architecture-specific seccomp profile for Firecracker."""

import argparse
import platform
import sys
from pathlib import Path
from urllib.request import urlretrieve


FIRECRACKER_REPO = "https://raw.githubusercontent.com/firecracker-microvm/firecracker"
DEFAULT_VERSION = "v1.7.0"

ARCH_MAP = {
    "x86_64": "x86_64-unknown-linux-musl.json",
    "aarch64": "aarch64-unknown-linux-musl.json",
    "arm64": "aarch64-unknown-linux-musl.json",
}


def detect_architecture() -> str:
    """Detect host architecture."""
    machine = platform.machine()
    if machine not in ARCH_MAP:
        print(f"Unsupported architecture: {machine}", file=sys.stderr)
        print(f"Supported: {', '.join(ARCH_MAP.keys())}", file=sys.stderr)
        sys.exit(1)
    return machine


def download_seccomp_profile(
    output_dir: Path,
    version: str = DEFAULT_VERSION,
    arch: str | None = None,
) -> Path:
    """Download seccomp profile for the specified architecture."""
    if arch is None:
        arch = detect_architecture()
    
    profile_filename = ARCH_MAP[arch]
    url = f"{FIRECRACKER_REPO}/{version}/resources/seccomp/{profile_filename}"
    output_path = output_dir / f"seccomp-{arch}.json"
    
    print(f"Downloading seccomp profile for {arch}...")
    print(f"  From: {url}")
    print(f"  To: {output_path}")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    urlretrieve(url, output_path)
    
    print(f"✓ Downloaded seccomp profile: {output_path}")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Download Firecracker seccomp profile for current architecture"
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory to save the seccomp profile",
    )
    parser.add_argument(
        "--version",
        default=DEFAULT_VERSION,
        help=f"Firecracker version (default: {DEFAULT_VERSION})",
    )
    parser.add_argument(
        "--arch",
        choices=list(ARCH_MAP.keys()),
        help="Override architecture detection",
    )
    
    args = parser.parse_args()
    
    try:
        output_path = download_seccomp_profile(
            args.output_dir,
            version=args.version,
            arch=args.arch,
        )
        print(f"\nTo use this profile, set:")
        print(f"  export NIMBUS_SECCOMP_FILTER={output_path}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
