from __future__ import annotations

import argparse
import json

import pytest

from nimbus.cli import admin


@pytest.mark.asyncio
async def test_run_tokens_list_outputs_summary(monkeypatch, capsys):
    args = argparse.Namespace(
        base_url="http://localhost:8000",
        admin_token="secret",
        json=True,
        command="tokens",
        tokens_cmd="list",
        history_limit=0,
    )

    async def fake_fetch(base_url: str, token: str):
        return [
            {
                "agent_id": "agent-1",
                "token_version": 2,
                "rotated_at": "2024-01-01T00:00:00+00:00",
                "ttl_seconds": 3600,
            }
        ]

    monkeypatch.setattr(admin, "fetch_token_inventory", fake_fetch)

    async def fake_audit(base_url: str, token: str, limit: int):
        return []

    monkeypatch.setattr(admin, "fetch_token_audit", fake_audit)

    await admin.run_tokens_list(args)
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["inventory"][0]["agent_id"] == "agent-1"
    assert payload["summary"]["total_agents"] == 1


@pytest.mark.asyncio
async def test_run_tokens_list_includes_history(monkeypatch, capsys):
    args = argparse.Namespace(
        base_url="http://localhost:8000",
        admin_token="secret",
        json=False,
        command="tokens",
        tokens_cmd="list",
        history_limit=2,
    )

    async def fake_fetch(base_url: str, token: str):
        return []

    async def fake_audit(base_url: str, token: str, limit: int):
        return [
            {
                "agent_id": "agent-1",
                "token_version": 3,
                "rotated_by": "admin",
                "rotated_at": "2024-01-01T00:00:00+00:00",
                "ttl_seconds": 3600,
                "id": 1,
            }
        ]

    monkeypatch.setattr(admin, "fetch_token_inventory", fake_fetch)
    monkeypatch.setattr(admin, "fetch_token_audit", fake_audit)

    await admin.run_tokens_list(args)
    output = capsys.readouterr().out
    assert "Recent rotations" in output
    assert "agent=agent-1" in output


@pytest.mark.asyncio
async def test_run_tokens_rotate_prints_result(monkeypatch, capsys):
    args = argparse.Namespace(
        base_url="http://localhost:8000",
        admin_token="secret",
        agent_id="agent-2",
        ttl=1800,
        json=False,
        command="tokens",
        tokens_cmd="rotate",
        history_limit=0,
    )

    async def fake_rotate(base_url: str, token: str, agent_id: str, ttl: int):
        return {
            "agent_id": agent_id,
            "version": 3,
            "ttl_seconds": ttl,
            "expires_at": "2024-01-01T02:00:00+00:00",
            "token": "abc",
        }

    monkeypatch.setattr(admin, "rotate_agent_token", fake_rotate)

    await admin.run_tokens_rotate(args)
    output = capsys.readouterr().out
    assert "Rotated token for agent-2" in output
    assert "TTL seconds: 1800" in output
