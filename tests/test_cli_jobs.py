from __future__ import annotations

import argparse
import json

import pytest

from nimbus.cli import jobs


def _namespace(**kwargs):
    return argparse.Namespace(**kwargs)


@pytest.mark.asyncio
async def test_cli_jobs_recent_plain(monkeypatch, capsys):
    sample_jobs = [
        {
            "job_id": 1,
            "status": "queued",
            "agent_id": None,
            "repo_full_name": "acme/repo",
            "queued_at": None,
            "updated_at": None,
        }
    ]

    async def fake_recent(
        base_url: str,
        token: str,
        limit: int,
        *,
        label=None,
        status=None,
        metadata_key=None,
        metadata_value=None,
    ):  # noqa: ANN001
        assert limit == 3
        assert label is None
        assert status is None
        assert metadata_key is None
        assert metadata_value is None
        return sample_jobs

    monkeypatch.setattr(
        jobs,
        "parse_args",
        lambda: _namespace(
            base_url="https://cp",
            token="secret",
            command="recent",
            limit=3,
            label=None,
            status=None,
            metadata_key=None,
            metadata_value=None,
            with_metadata=False,
            json=False,
        ),
    )
    monkeypatch.setattr(jobs, "fetch_recent_jobs", fake_recent)
    monkeypatch.setattr(jobs, "fetch_status", lambda *a, **k: None)

    await jobs.run()
    output = capsys.readouterr().out
    assert "job_id" in output
    assert "acme/repo" in output


@pytest.mark.asyncio
async def test_cli_jobs_recent_json(monkeypatch, capsys):
    async def fake_recent(
        base_url: str,
        token: str,
        limit: int,
        *,
        label=None,
        status=None,
        metadata_key=None,
        metadata_value=None,
    ):  # noqa: ANN001
        assert label == "gpu"
        assert status == "running"
        assert metadata_key == "lr"
        assert metadata_value == "0.01"
        return [{"job_id": 2}]

    monkeypatch.setattr(
        jobs,
        "parse_args",
        lambda: _namespace(
            base_url="https://cp",
            token="secret",
            command="recent",
            limit=1,
            label="gpu",
            status="running",
            metadata_key="lr",
            metadata_value="0.01",
            with_metadata=False,
            json=True,
        ),
    )
    monkeypatch.setattr(jobs, "fetch_recent_jobs", fake_recent)
    monkeypatch.setattr(jobs, "fetch_status", lambda *a, **k: None)

    await jobs.run()
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["job_id"] == 2


@pytest.mark.asyncio
async def test_cli_jobs_recent_with_metadata(monkeypatch, capsys):
    sample_jobs = [
        {
            "job_id": 3,
            "status": "succeeded",
            "agent_id": "agent-7",
            "repo_full_name": "acme/repo",
            "queued_at": None,
            "updated_at": None,
            "metadata": {"batch": "32", "lr": "0.10"},
        }
    ]

    async def fake_recent(
        base_url: str,
        token: str,
        limit: int,
        *,
        label=None,
        status=None,
        metadata_key=None,
        metadata_value=None,
    ):  # noqa: ANN001
        return sample_jobs

    monkeypatch.setattr(
        jobs,
        "parse_args",
        lambda: _namespace(
            base_url="https://cp",
            token="secret",
            command="recent",
            limit=5,
            label=None,
            status=None,
            metadata_key=None,
            metadata_value=None,
            with_metadata=True,
            json=False,
        ),
    )
    monkeypatch.setattr(jobs, "fetch_recent_jobs", fake_recent)
    monkeypatch.setattr(jobs, "fetch_status", lambda *a, **k: None)

    await jobs.run()
    output = capsys.readouterr().out
    assert "meta: batch=32, lr=0.10" in output


@pytest.mark.asyncio
async def test_cli_jobs_status_plain(monkeypatch, capsys):
    async def fake_status(base_url: str, token: str):  # noqa: ANN001
        return {"queue_length": 4, "jobs_by_status": {"queued": 3, "running": 1}}

    monkeypatch.setattr(
        jobs,
        "parse_args",
        lambda: _namespace(
            base_url="https://cp",
            token="secret",
            command="status",
            json=False,
        ),
    )
    monkeypatch.setattr(jobs, "fetch_status", fake_status)

    await jobs.run()
    output = capsys.readouterr().out
    assert "Queue length: 4" in output
    assert "queued: 3" in output


@pytest.mark.asyncio
async def test_cli_jobs_status_json(monkeypatch, capsys):
    async def fake_status(base_url: str, token: str):  # noqa: ANN001
        return {"queue_length": 1}

    monkeypatch.setattr(
        jobs,
        "parse_args",
        lambda: _namespace(
            base_url="https://cp",
            token="secret",
            command="status",
            json=True,
        ),
    )
    monkeypatch.setattr(jobs, "fetch_status", fake_status)

    await jobs.run()
    payload = json.loads(capsys.readouterr().out)
    assert payload["queue_length"] == 1
