from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from nimbus.cli.report import (
    summarize_agent_tokens,
    summarize_cache,
    summarize_jobs,
    summarize_logs,
    run_jobs,
    run_overview,
    run_metadata,
    run_metadata_presets,
)


def test_summarize_jobs_counts_and_timeline() -> None:
    status_payload = {"queue_length": 4, "jobs_by_status": {"queued": 3, "running": 1}}
    recent_jobs = [
        {
            "job_id": 1,
            "status": "queued",
            "agent_id": None,
            "repo_full_name": "acme/repo",
            "updated_at": "2024-01-01T10:00:00+00:00",
        },
        {
            "job_id": 2,
            "status": "running",
            "agent_id": "agent-1",
            "repo_full_name": "acme/repo",
            "updated_at": "2024-01-01T11:00:00+00:00",
        },
        {
            "job_id": 3,
            "status": "queued",
            "agent_id": "agent-2",
            "repo_full_name": "acme/other",
            "updated_at": "2024-01-01T12:00:00+00:00",
            "metadata": {"lr": "0.01"},
        },
        {
            "job_id": 4,
            "status": "queued",
            "agent_id": "agent-3",
            "repo_full_name": "acme/repo",
            "updated_at": "2024-01-01T13:00:00+00:00",
            "metadata": {"lr": "0.01", "batch": "16"},
        },
    ]

    summary = summarize_jobs(status_payload, recent_jobs)
    assert summary["queue_length"] == 4
    assert summary["jobs_by_status"] == {"queued": 3, "running": 1}
    assert summary["top_repositories"] == {"acme/repo": 3, "acme/other": 1}
    assert summary["top_agents"]["agent-1"] == 1
    assert summary["top_agents"]["agent-2"] == 1
    assert summary["top_agents"]["agent-3"] == 1
    assert summary["top_agents"]["unassigned"] == 1
    assert summary["recent_timeline"][0]["job_id"] == 4
    assert summary["top_metadata"][0] == {"key": "lr", "value": "0.01", "count": 2}


def test_summarize_cache_aggregates_hits_and_bytes() -> None:
    status_payload = {
        "backend": "local",
        "storage_path": "/cache",
        "total_entries": 10,
        "top_entries": [
            {
                "cache_key": "org/project/a",
                "total_hits": 5,
                "total_misses": 1,
                "total_bytes": 1024,
            },
            {
                "cache_key": "org/project/b",
                "total_hits": 2,
                "total_misses": 0,
                "total_bytes": 2048,
            },
        ],
    }

    summary = summarize_cache(status_payload, top=2)
    assert summary["backend"] == "local"
    assert summary["top_hits"] == 7
    assert summary["top_misses"] == 1
    assert summary["top_bytes"] == 3072
    assert len(summary["top_entries"]) == 2
    assert summary["hit_ratio"] == 0.875
    assert summary["stale_entry_count"] == 0
    assert summary["eviction_candidates"] == []


def test_summarize_cache_eviction_candidates() -> None:
    status_payload = {
        "top_entries": [
            {"cache_key": "a", "total_hits": 0, "total_misses": 3, "total_bytes": 10, "last_access": "2024-01-01T00:00:00+00:00"},
            {"cache_key": "b", "total_hits": 0, "total_misses": 1, "total_bytes": 5, "last_access": "2024-01-02T00:00:00+00:00"},
            {"cache_key": "c", "total_hits": 2, "total_misses": 0, "total_bytes": 7, "last_access": "2024-01-03T00:00:00+00:00"},
        ]
    }

    summary = summarize_cache(status_payload, top=2)
    assert summary["stale_entry_count"] == 2
    assert [entry["cache_key"] for entry in summary["eviction_candidates"]] == ["a", "b"]


def test_summarize_agent_tokens_flags_expiring() -> None:
    now = datetime.now(timezone.utc)
    records = [
        {
            "agent_id": "agent-1",
            "token_version": 2,
            "rotated_at": (now - timedelta(hours=1)).isoformat(),
            "ttl_seconds": 7200,
        },
        {
            "agent_id": "agent-2",
            "token_version": 5,
            "rotated_at": (now - timedelta(hours=10)).isoformat(),
            "ttl_seconds": 3600,
        },
    ]

    summary = summarize_agent_tokens(records)
    assert summary["total_agents"] == 2
    assert "agent-2" in summary["expired_agents"]
    assert summary["entries"][0]["agent_id"] == "agent-1"


def test_summarize_logs_counts_levels_and_samples() -> None:
    log_entries = [
        {"job_id": 1, "level": "info", "timestamp": "t1", "message": "log1"},
        {"job_id": 1, "level": "error", "timestamp": "t2", "message": "log2"},
        {"job_id": 2, "level": "info", "timestamp": "t3", "message": "log3"},
    ]

    summary = summarize_logs(log_entries)
    assert summary["entry_count"] == 3
    assert summary["levels"] == {"info": 2, "error": 1}
    assert summary["jobs"][1] == 2
    assert summary["jobs"][2] == 1
    assert len(summary["samples"]) == 3


@pytest.mark.asyncio
async def test_run_jobs_passes_metadata_filters(monkeypatch, capsys):
    async def fake_fetch_recent(
        base_url: str,
        token: str,
        limit: int,
        *,
        label=None,
        status=None,
        metadata_key=None,
        metadata_value=None,
    ):
        assert metadata_key == "lr"
        assert metadata_value == "0.1"
        return []

    async def fake_fetch_status(base_url: str, token: str):
        return {"queue_length": 0, "jobs_by_status": {}}

    monkeypatch.setattr("nimbus.cli.report.fetch_recent_jobs", fake_fetch_recent)
    monkeypatch.setattr("nimbus.cli.report.fetch_status", fake_fetch_status)

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        limit=10,
        metadata_key="lr",
        metadata_value="0.1",
        json=True,
    )
    await run_jobs(args)
    payload = capsys.readouterr().out.strip()
    assert payload  # JSON payload printed


@pytest.mark.asyncio
async def test_run_overview_passes_metadata_filters(monkeypatch, capsys):
    async def fake_fetch_recent(
        base_url: str,
        token: str,
        limit: int,
        *,
        label=None,
        status=None,
        metadata_key=None,
        metadata_value=None,
    ):
        assert metadata_key == "lr"
        assert metadata_value == "0.1"
        return []

    async def fake_fetch_status(base_url: str, token: str):
        return {"queue_length": 0, "jobs_by_status": {}}

    async def fake_fetch_cache(cache_url: str, cache_token: str | None):
        return {"top_entries": []}

    async def fake_fetch_logs(logs_url: str, job_id: int | None, contains: str | None, limit: int):
        return []

    async def fake_metadata_summary(
        base_url: str,
        token: str,
        key: str,
        *,
        limit: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        assert key == "lr"
        return [{"value": "0.1", "count": 5}]

    async def fake_metadata_outcomes(
        base_url: str,
        token: str,
        key: str,
        *,
        limit: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        return [{"value": "0.1", "total": 5, "succeeded": 4, "failed": 1}]

    async def fake_metadata_trend(
        base_url: str,
        token: str,
        key: str,
        *,
        bucket_hours: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        return [{"window_start": "2024-01-01T00:00:00Z", "total": 5, "succeeded": 4, "failed": 1}]

    async def fake_metadata_presets(*args, **kwargs):  # noqa: ANN001
        return []

    monkeypatch.setattr("nimbus.cli.report.fetch_recent_jobs", fake_fetch_recent)
    monkeypatch.setattr("nimbus.cli.report.fetch_status", fake_fetch_status)
    monkeypatch.setattr("nimbus.cli.report.fetch_cache_status", fake_fetch_cache)
    monkeypatch.setattr("nimbus.cli.report.fetch_logs", fake_fetch_logs)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_summary", fake_metadata_summary)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_outcomes", fake_metadata_outcomes)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_trend", fake_metadata_trend)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_presets", fake_metadata_presets)

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        cache_url="https://cache",
        cache_token=None,
        logs_url="https://logs",
        job_limit=5,
        job_metadata_key="lr",
        job_metadata_value="0.1",
        log_limit=5,
        json=True,
    )
    await run_overview(args)
    payload = capsys.readouterr().out.strip()
    assert payload  # JSON payload printed


@pytest.mark.asyncio
async def test_run_metadata(monkeypatch, capsys):
    async def fake_summary(
        base_url: str,
        token: str,
        key: str,
        *,
        limit: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        assert key == "lr"
        return [{"value": "0.05", "count": 3}]

    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_summary", fake_summary)

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        key="lr",
        limit=10,
        hours_back=None,
        org_id=None,
        json=False,
        with_outcomes=False,
        trend=False,
    )
    await run_metadata(args)
    output = capsys.readouterr().out
    assert "0.05" in output


@pytest.mark.asyncio
async def test_run_metadata_with_outcomes(monkeypatch, capsys):
    async def fake_summary(
        base_url: str,
        token: str,
        key: str,
        *,
        limit: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        return [{"value": "0.1", "count": 4}]

    async def fake_outcomes(
        base_url: str,
        token: str,
        key: str,
        *,
        limit: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        return [{"value": "0.1", "total": 4, "succeeded": 3, "failed": 1}]

    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_summary", fake_summary)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_outcomes", fake_outcomes)

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        key="lr",
        limit=10,
        hours_back=None,
        org_id=None,
        json=False,
        with_outcomes=True,
    )
    await run_metadata(args)
    output = capsys.readouterr().out
    assert "success=3" in output


@pytest.mark.asyncio
async def test_run_metadata_with_trend(monkeypatch, capsys):
    async def fake_summary(
        base_url: str,
        token: str,
        key: str,
        *,
        limit: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        return [{"value": "0.1", "count": 5}]

    async def fake_trend(
        base_url: str,
        token: str,
        key: str,
        *,
        bucket_hours: int,
        hours_back: int | None,
        org_id: int | None,
    ):
        return [{"window_start": "2024-01-01T00:00:00Z", "total": 5, "succeeded": 4, "failed": 1}]

    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_summary", fake_summary)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_trend", fake_trend)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_outcomes", lambda *a, **k: [])

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        key="lr",
        limit=10,
        hours_back=None,
        org_id=None,
        json=False,
        with_outcomes=False,
        trend=True,
        bucket_hours=1,
    )
    await run_metadata(args)
    output = capsys.readouterr().out
    assert "success=80.0%" in output


@pytest.mark.asyncio
async def test_run_overview_with_presets(monkeypatch, capsys):
    async def fake_fetch_recent(*args, **kwargs):  # noqa: ANN001
        return []

    async def fake_fetch_status(*args, **kwargs):  # noqa: ANN001
        return {"queue_length": 0, "jobs_by_status": {}}

    async def fake_fetch_cache(*args, **kwargs):  # noqa: ANN001
        return {"top_entries": []}

    async def fake_fetch_logs(*args, **kwargs):  # noqa: ANN001
        return []

    async def fake_fetch_metadata_presets(*args, **kwargs):  # noqa: ANN001
        return [
            {
                "key": "lr",
                "summary": [{"value": "0.1", "count": 5}],
                "outcomes": [],
                "trend": [],
            }
        ]

    monkeypatch.setattr("nimbus.cli.report.fetch_recent_jobs", fake_fetch_recent)
    monkeypatch.setattr("nimbus.cli.report.fetch_status", fake_fetch_status)
    monkeypatch.setattr("nimbus.cli.report.fetch_cache_status", fake_fetch_cache)
    monkeypatch.setattr("nimbus.cli.report.fetch_logs", fake_fetch_logs)
    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_presets", fake_fetch_metadata_presets)

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        cache_url="https://cache",
        cache_token=None,
        logs_url="https://logs",
        job_limit=5,
        job_metadata_key=None,
        job_metadata_value=None,
        log_limit=5,
        metadata_presets=True,
        metadata_preset_keys=None,
        metadata_preset_limit=5,
        metadata_preset_hours=24,
        json=False,
    )

    await run_overview(args)
    output = capsys.readouterr().out
    assert "Metadata presets" in output


@pytest.mark.asyncio
async def test_run_metadata_presets_prints_summary(monkeypatch, capsys):
    async def fake_fetch_presets(
        base_url: str,
        token: str,
        *,
        keys=None,
        limit=None,
        hours_back=None,
        bucket_hours=None,
        org_id=None,
    ):
        assert base_url == "https://cp"
        assert token == "secret"
        assert keys is None
        assert limit == 5
        assert bucket_hours == 24
        return [
            {
                "key": "lr",
                "summary": [{"value": "0.1", "count": 12}],
                "outcomes": [{"value": "0.1", "total": 12, "succeeded": 9, "failed": 3}],
                "trend": [{"window_start": "2024-01-01T00:00:00Z", "total": 4, "succeeded": 3, "failed": 1}],
            }
        ]

    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_presets", fake_fetch_presets)

    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        keys=None,
        limit=5,
        hours_back=None,
        bucket_hours=24,
        org_id=None,
        json=False,
        output=None,
    )

    await run_metadata_presets(args)
    output = capsys.readouterr().out
    assert "Metadata presets (1 bundles)" in output
    assert "- lr" in output
    assert "0.1: 12" in output
    assert "success=75.0%" in output


@pytest.mark.asyncio
async def test_run_metadata_presets_writes_file(monkeypatch, tmp_path, capsys):
    async def fake_fetch_presets(
        base_url: str,
        token: str,
        *,
        keys=None,
        limit=None,
        hours_back=None,
        bucket_hours=None,
        org_id=None,
    ):
        assert base_url == "https://cp"
        assert token == "secret"
        assert keys == "batch"
        assert limit == 3
        assert hours_back == 12
        assert bucket_hours == 6
        assert org_id == 42
        return [{"key": "batch", "summary": [{"value": "32", "count": 4}]}]

    monkeypatch.setattr("nimbus.cli.report.fetch_metadata_presets", fake_fetch_presets)

    output_path = tmp_path / "presets.json"
    args = argparse.Namespace(
        base_url="https://cp",
        token="secret",
        keys="batch",
        limit=3,
        hours_back=12,
        bucket_hours=6,
        org_id=42,
        json=False,
        output=str(output_path),
    )

    await run_metadata_presets(args)
    captured = capsys.readouterr().out
    assert output_path.exists()
    file_content = output_path.read_text()
    assert '"batch"' in file_content
    assert "Wrote 1 preset bundles" in captured
