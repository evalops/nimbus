from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(os.getenv("SMITH_RUN_COMPOSE_TESTS") != "1", reason="Set SMITH_RUN_COMPOSE_TESTS=1 to enable compose smoke tests")
def test_compose_configuration(tmp_path: Path):
    if shutil.which("docker") is None:
        pytest.skip("docker binary not available")

    compose_file = Path(__file__).resolve().parents[2] / "compose.yaml"
    env_path = tmp_path / ".env"
    env_path.write_text(
        "\n".join(
            [
                "SMITH_GITHUB_APP_ID=1",
                "SMITH_GITHUB_APP_PRIVATE_KEY=replace-with-key",
                "SMITH_GITHUB_APP_INSTALLATION_ID=1",
                "SMITH_GITHUB_WEBHOOK_SECRET=secret",
                "SMITH_AGENT_TOKEN_SECRET=agent-secret",
                "SMITH_CACHE_SHARED_SECRET=cache-secret",
                "SMITH_JWT_SECRET=jwt-secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_path),
            "-f",
            str(compose_file),
            "config",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"docker compose config failed: {result.stderr}")
