from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from unittest import mock

import pytest


def _load_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "compose_manager.py"
    spec = importlib.util.spec_from_file_location("compose_manager", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_build_args_with_profile_and_detach():
    options = argparse.Namespace(command="up", profile="agent", detach=True, follow=False)
    compose_manager = _load_module()
    args = compose_manager.build_args(options)
    assert args == ["up", "-d", "--profile", "agent"]


def test_build_args_logs_follow():
    options = argparse.Namespace(command="logs", profile=None, detach=False, follow=True)
    compose_manager = _load_module()
    args = compose_manager.build_args(options)
    assert args == ["logs", "--follow"]


def test_main_runs_compose(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("SMITH=1\n")
    compose_file = tmp_path / "compose.yaml"
    compose_file.write_text("version: '3'\n")

    compose_manager = _load_module()
    with mock.patch.object(compose_manager, "run_compose", return_value=0) as run_mock:
        with mock.patch.object(compose_manager, "parse_args") as parse_mock:
            parse_mock.return_value = argparse.Namespace(
                command="config",
                env_file=str(env_file),
                compose_file=str(compose_file),
                profile=None,
                detach=False,
                follow=False,
            )
            compose_manager.main()
    run_mock.assert_called_once()


def test_main_fails_without_env(tmp_path: Path):
    compose_file = tmp_path / "compose.yaml"
    compose_file.write_text("version: '3'\n")

    compose_manager = _load_module()
    with mock.patch.object(compose_manager, "parse_args") as parse_mock:
        parse_mock.return_value = argparse.Namespace(
            command="config",
            env_file=str(tmp_path / ".env"),
            compose_file=str(compose_file),
            profile=None,
            detach=False,
            follow=False,
        )
        with pytest.raises(FileNotFoundError):
            compose_manager.main()
