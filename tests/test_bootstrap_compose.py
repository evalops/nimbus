from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest

from smith.common.security import decode_agent_token_payload


def _load_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_compose.py"
    spec = importlib.util.spec_from_file_location("bootstrap_compose", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_bootstrap_writes_env_and_generates_token(tmp_path: Path):
    output = tmp_path / ".env"
    module = _load_module()
    token = module.bootstrap_env(output, force=True)

    assert output.exists()
    contents = output.read_text().splitlines()
    env = dict(line.split("=", 1) for line in contents[1:])

    assert env["SMITH_JWT_SECRET"]
    assert env["SMITH_AGENT_TOKEN_SECRET"]
    assert env["SMITH_CACHE_SHARED_SECRET"]

    subject, version = decode_agent_token_payload(env["SMITH_JWT_SECRET"], token)
    assert subject == "admin"
    assert version == 0


def test_bootstrap_respects_existing_file(tmp_path: Path):
    output = tmp_path / ".env"
    output.write_text("SMITH_JWT_SECRET=existing\n")

    module = _load_module()
    with pytest.raises(FileExistsError):
        module.bootstrap_env(output)


def test_bootstrap_mints_agent_token_when_requested(tmp_path: Path):
    output = tmp_path / ".env"
    secrets_file = tmp_path / "tokens.json"
    module = _load_module()

    fake_token = "minted-agent-token"

    with mock.patch.object(module, "_mint_agent_token_remote", return_value=fake_token) as mocked:
        module.bootstrap_env(
            output,
            force=True,
            control_plane_url="http://localhost:8000",
            admin_token="admin-jwt",
            agent_id="agent-42",
            agent_ttl=900,
            secrets_output=secrets_file,
        )

    mocked.assert_called_once_with(
        "http://localhost:8000",
        "admin-jwt",
        agent_id="agent-42",
        ttl_seconds=900,
    )

    contents = output.read_text().splitlines()
    env = dict(line.split("=", 1) for line in contents[1:])
    assert env["SMITH_CONTROL_PLANE_TOKEN"] == fake_token

    secrets_payload = json.loads(secrets_file.read_text())
    assert secrets_payload["agent_token"] == fake_token
    assert secrets_payload["agent_id"] == "agent-42"
