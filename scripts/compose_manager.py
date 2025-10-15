from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def run_compose(env_file: Path, compose_file: Path, args: list[str]) -> int:
    command = ["docker", "compose", "--env-file", str(env_file), "-f", str(compose_file)] + args
    result = subprocess.run(command, check=False)
    return result.returncode


def ensure_env_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Env file not found at {path}. Run the bootstrap script first.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage Nimbus docker compose workflows")
    parser.add_argument("command", choices=["up", "down", "logs", "config", "ps"], help="Compose action to perform")
    parser.add_argument("--env-file", default=".env", help="Path to compose env file")
    parser.add_argument("--compose-file", default="compose.yaml", help="Path to compose file")
    parser.add_argument("--profile", help="Compose profile (e.g. agent)")
    parser.add_argument("--detach", action="store_true", help="Run docker compose up in detached mode")
    parser.add_argument("--follow", action="store_true", help="Follow logs output")
    return parser.parse_args()


def build_args(options: argparse.Namespace) -> list[str]:
    args: list[str] = [options.command]
    if options.command == "up" and options.detach:
        args.append("-d")
    if options.profile:
        args.extend(["--profile", options.profile])
    if options.command == "logs" and options.follow:
        args.append("--follow")
    return args


def main() -> None:
    options = parse_args()
    env_file = Path(options.env_file)
    compose_file = Path(options.compose_file)
    ensure_env_file(env_file)
    args = build_args(options)
    code = run_compose(env_file, compose_file, args)
    if code != 0:
        sys.exit(code)


if __name__ == "__main__":
    main()
