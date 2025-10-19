#!/usr/bin/env python3
"""Script to create golden Firecracker snapshots for fast boot."""

import asyncio
import argparse
import os
from pathlib import Path

from src.nimbus.common.settings import HostAgentSettings
from src.nimbus.tools.snapshot_builder import SnapshotBuilder


async def main():
    """Create a golden snapshot for Firecracker fast boot."""
    parser = argparse.ArgumentParser(description="Create Firecracker golden snapshot")
    parser.add_argument("--output-dir", type=Path, default=Path("./snapshots"),
                       help="Directory to store snapshot files")
    parser.add_argument("--pre-install", action="append", default=[],
                       help="Commands to run before snapshotting (can be repeated)")
    parser.add_argument("--snapshot-name", default="golden",
                       help="Name prefix for snapshot files")
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    state_path = args.output_dir / f"{args.snapshot_name}.vmstate"
    memory_path = args.output_dir / f"{args.snapshot_name}.mem"
    
    # Set up minimal environment if not already configured
    env_defaults = {
        "NIMBUS_AGENT_ID": "snapshot-builder",
        "NIMBUS_CONTROL_PLANE_URL": "http://localhost:8000",
        "NIMBUS_CONTROL_PLANE_TOKEN": "unused-for-snapshot-creation",
    }
    
    for key, value in env_defaults.items():
        os.environ.setdefault(key, value)
    
    # Validate required environment
    required_vars = ["NIMBUS_ROOTFS_IMAGE", "NIMBUS_KERNEL_IMAGE"]
    missing = [var for var in required_vars if not os.getenv(var)]
    
    if missing:
        print(f"❌ Missing required environment variables: {missing}")
        print("\nRequired setup:")
        print("  export NIMBUS_ROOTFS_IMAGE=/path/to/rootfs.ext4")
        print("  export NIMBUS_KERNEL_IMAGE=/path/to/vmlinux") 
        return 1
    
    try:
        settings = HostAgentSettings()
        builder = SnapshotBuilder(settings)
        
        print(f"🔥 Creating golden snapshot...")
        print(f"📁 Output: {state_path}, {memory_path}")
        print(f"💾 Rootfs: {settings.rootfs_image_path}")
        print(f"🧠 Kernel: {settings.kernel_image_path}")
        
        if args.pre_install:
            print(f"⚙️  Pre-install commands: {args.pre_install}")
        
        await builder.create_golden_snapshot(
            state_path, 
            memory_path,
            pre_boot_commands=args.pre_install or None
        )
        
        print("✅ Golden snapshot created successfully!")
        print(f"📊 State file size: {state_path.stat().st_size // 1024 // 1024}MB")
        print(f"📊 Memory file size: {memory_path.stat().st_size // 1024 // 1024}MB")
        
        # Update environment file template
        env_template = f"""
# Snapshot configuration for fast Firecracker boot
export NIMBUS_SNAPSHOT_STATE_PATH="{state_path.absolute()}"
export NIMBUS_SNAPSHOT_MEMORY_PATH="{memory_path.absolute()}"
export NIMBUS_SNAPSHOT_ENABLE_DIFF=true

# Usage: source this file before starting nimbus host agent
# Boot time improvement: ~1.3s → ~80ms (16x faster)
"""
        
        env_file = args.output_dir / "snapshot.env"
        env_file.write_text(env_template.strip())
        
        print(f"📄 Environment template: {env_file}")
        print("💡 To use: source snapshot.env && nimbus-host-agent")
        
        return 0
        
    except Exception as e:
        print(f"❌ Snapshot creation failed: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
