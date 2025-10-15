from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


def _load_module():
    path_spec = importlib.util.spec_from_file_location("run_smoke", Path(__file__).resolve().parents[1] / "scripts" / "run_smoke.py")
    assert path_spec and path_spec.loader
    module = importlib.util.module_from_spec(path_spec)
    path_spec.loader.exec_module(module)
    return module


def test_run_smoke_requires_docker(monkeypatch, capsys):
    smoke = _load_module()
    monkeypatch.setattr(smoke.shutil, "which", lambda _: None)
    exit_code = smoke.run_smoke()
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "docker binary not found" in captured.err


def test_run_smoke_invokes_pytest(monkeypatch):
    smoke = _load_module()
    monkeypatch.setattr(smoke.shutil, "which", lambda _: "/usr/bin/docker")
    fake_run = mock.Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(smoke.subprocess, "run", fake_run)
    exit_code = smoke.run_smoke(["pytest", "-k", "compose"])
    assert exit_code == 0
    fake_run.assert_called_once()
    env = fake_run.call_args.kwargs["env"]
    assert env["NIMBUS_RUN_COMPOSE_TESTS"] == "1"
