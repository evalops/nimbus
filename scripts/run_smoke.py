from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Sequence


def run_smoke(pytest_args: Sequence[str] | None = None) -> int:
    if shutil.which("docker") is None:
        print("docker binary not found; install Docker to run smoke tests", file=sys.stderr)
        return 2

    if pytest_args is None:
        pytest_args = ["pytest", "tests/system/test_compose_stack.py"]

    env = os.environ.copy()
    env["NIMBUS_RUN_COMPOSE_TESTS"] = "1"
    result = subprocess.run(list(pytest_args), env=env)
    return result.returncode


def main() -> None:
    code = run_smoke()
    sys.exit(code)


if __name__ == "__main__":
    main()
