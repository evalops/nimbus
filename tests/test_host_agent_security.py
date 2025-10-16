from __future__ import annotations

import builtins
import sys

import pytest

from nimbus.host_agent import security


class DummyLogger:
    def __init__(self) -> None:
        self.warning_called = False
        self.error_called = False

    def warning(self, *args, **kwargs) -> None:  # noqa: ANN001
        self.warning_called = True

    def error(self, *args, **kwargs) -> None:  # noqa: ANN001
        self.error_called = True

    def info(self, *args, **kwargs) -> None:  # noqa: ANN001
        return None

    def debug(self, *args, **kwargs) -> None:  # noqa: ANN001
        return None


def test_check_capabilities_non_root(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr(security, "LOGGER", logger)
    monkeypatch.setattr(security.os, "geteuid", lambda: 1000)

    # Without python-prctl installed this should simply log a debug message and succeed
    security.check_capabilities()
    assert logger.error_called is False


def test_check_capabilities_raises_for_root(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr(security, "LOGGER", logger)
    monkeypatch.setattr(security.os, "geteuid", lambda: 0)

    with pytest.raises(RuntimeError):
        security.check_capabilities()
    assert logger.error_called is True


def test_drop_capabilities_without_prctl(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr(security, "LOGGER", logger)

    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):  # noqa: ANN001
        if name == "prctl":
            raise ImportError("no prctl")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.delitem(sys.modules, "prctl", raising=False)

    security.drop_capabilities()
    assert logger.warning_called is True
