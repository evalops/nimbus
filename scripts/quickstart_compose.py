from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx

from scripts.bootstrap_compose import bootstrap_env


DEFAULT_ENV_FILE = Path(".env.local")
DEFAULT_COMPOSE_FILE = Path("compose.yaml")
DEFAULT_HEALTH_URL = "http://127.0.0.1:8000/healthz"


def _ensure_docker() -> None:
    if shutil.which("docker") is None:
        raise RuntimeError("docker binary not found in PATH. Install Docker before running the quickstart.")


def _bootstrap(env_path: Path, force: bool) -> None:
    if env_path.exists() and not force:
        return
    bootstrap_env(env_path, force=True if force else False, print_admin_token=False)


def _compose_up(env_path: Path, compose_file: Path, include_agent: bool, detach: bool) -> None:
    args: list[str] = [
        "docker",
        "compose",
        "--env-file",
        str(env_path),
        "-f",
        str(compose_file),
        "up",
    ]
    if detach:
        args.append("-d")
    if include_agent:
        args.extend(["--profile", "agent"])

    result = subprocess.run(args, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"docker compose up failed with exit code {result.returncode}")


def _wait_for_health(url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with httpx.Client(timeout=2.0) as client:
                response = client.get(url)
                if response.status_code == 200:
                    return
        except Exception as exc:  # noqa: BLE001 - we want to surface any connection issues
            last_exc = exc
        time.sleep(1.0)

    message = f"Timed out waiting for {url}"
    if last_exc:
        message += f": {last_exc}"
    raise RuntimeError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local Nimbus example stack with docker compose.")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE, help="Path for generated compose environment file.")
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=DEFAULT_COMPOSE_FILE,
        help="Compose file to use for the example stack.",
    )
    parser.add_argument("--force-bootstrap", action="store_true", help="Regenerate the env file even if it exists.")
    parser.add_argument("--with-agent", action="store_true", help="Start the host agent profile (requires Firecracker artifacts and /dev/kvm access).")
    parser.add_argument("--no-detach", action="store_true", help="Run docker compose up in the foreground.")
    parser.add_argument("--health-url", default=DEFAULT_HEALTH_URL, help="Health endpoint to poll after compose starts.")
    parser.add_argument("--health-timeout", type=float, default=60.0, help="Seconds to wait for the health endpoint to succeed.")
    return parser.parse_args()


def main() -> None:
    options = parse_args()
    try:
        _ensure_docker()
        _bootstrap(options.env_file, force=options.force_bootstrap)
        _compose_up(options.env_file, options.compose_file, include_agent=options.with_agent, detach=not options.no_detach)
        _wait_for_health(options.health_url, timeout=options.health_timeout)
    except Exception as exc:  # noqa: BLE001
        print(f"[quickstart] error: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Nimbus stack is ready!")
    print(f"- Control Plane: {options.health_url.replace('/healthz', '')}")
    print("- Dashboard: http://127.0.0.1:5173 (if web container enabled)")
    if options.with_agent:
        print("- Host agent profile started (Firecracker jobs available).")
    else:
        print("- Host agent profile not started; rerun with --with-agent once artifacts are prepared.")
    print(f"Environment variables saved to {options.env_file}")


if __name__ == "__main__":
    main()
