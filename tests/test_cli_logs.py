from __future__ import annotations

import argparse
import json

import pytest

from nimbus.cli import logs


def _namespace(**kwargs):
    return argparse.Namespace(**kwargs)


@pytest.mark.asyncio
async def test_cli_logs_prints_entries(monkeypatch, capsys):
    entries = [
        {"timestamp": "t1", "job_id": 1, "level": "info", "message": "hello"},
        {"timestamp": "t2", "job_id": 2, "level": "error", "message": "fail"},
    ]

    async def fake_fetch(url: str, params: dict[str, object]):  # noqa: ANN001
        assert params["limit"] == 50
        return entries

    monkeypatch.setattr(
        logs,
        "parse_args",
        lambda: _namespace(
            logs_url="https://logs", job_id=None, contains=None, limit=50, json=False
        ),
    )
    monkeypatch.setattr(logs, "fetch_logs", fake_fetch)

    await logs.run()
    output = capsys.readouterr().out
    assert "job=1" in output
    assert "hello" in output
    assert "job=2" in output


@pytest.mark.asyncio
async def test_cli_logs_json(monkeypatch, capsys):
    async def fake_fetch(url: str, params: dict[str, object]):  # noqa: ANN001
        return [
            {"timestamp": "t3", "job_id": 3, "level": "info", "message": "done"}
        ]

    monkeypatch.setattr(
        logs,
        "parse_args",
        lambda: _namespace(
            logs_url="https://logs", job_id=5, contains="abc", limit=10, json=True
        ),
    )
    monkeypatch.setattr(logs, "fetch_logs", fake_fetch)

    await logs.run()
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload[0]["job_id"] == 3


@pytest.mark.asyncio
async def test_cli_logs_no_entries(monkeypatch, capsys):
    async def fake_fetch(url: str, params: dict[str, object]):  # noqa: ANN001
        return []

    monkeypatch.setattr(
        logs,
        "parse_args",
        lambda: _namespace(
            logs_url="https://logs", job_id=None, contains=None, limit=5, json=False
        ),
    )
    monkeypatch.setattr(logs, "fetch_logs", fake_fetch)

    await logs.run()
    output = capsys.readouterr().out.strip()
    assert output == "No log entries found"
