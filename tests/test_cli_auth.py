from __future__ import annotations

import argparse
import json

import pytest

from nimbus.cli import auth


def _namespace(**kwargs):
    return argparse.Namespace(**kwargs)


def test_cli_auth_main_base_url(monkeypatch, capsys):
    response_payload = {"token": "abc123", "ttl_seconds": 7200}

    class DummyResponse:
        def raise_for_status(self) -> None:  # noqa: D401
            return None

        def json(self) -> dict[str, int | str]:
            return response_payload

    monkeypatch.setattr(
        auth,
        "parse_args",
        lambda: _namespace(
            agent_id="agent-1",
            ttl=3600,
            json=True,
            base_url="https://cp.example",
            admin_token="secret",
            secret=None,
        ),
    )
    monkeypatch.setattr(auth.httpx, "post", lambda *a, **k: DummyResponse())

    auth.main()
    output = json.loads(capsys.readouterr().out)
    assert output["agent_id"] == "agent-1"
    assert output["token"] == "abc123"
    assert output["ttl_seconds"] == 7200


def test_cli_auth_main_local_secret(monkeypatch, capsys):
    monkeypatch.setattr(
        auth,
        "parse_args",
        lambda: _namespace(
            agent_id="agent-2",
            ttl=1800,
            json=False,
            base_url=None,
            admin_token=None,
            secret="shared",
        ),
    )
    monkeypatch.setattr(auth, "mint_agent_token", lambda **_: "local-token")

    auth.main()
    output = capsys.readouterr().out.strip()
    assert output == "local-token"


def test_cli_auth_requires_admin_token(monkeypatch):
    monkeypatch.setattr(
        auth,
        "parse_args",
        lambda: _namespace(
            agent_id="agent-3",
            ttl=3600,
            json=False,
            base_url="https://cp.example",
            admin_token=None,
            secret=None,
        ),
    )

    with pytest.raises(SystemExit):
        auth.main()


def test_cli_auth_requires_secret(monkeypatch):
    monkeypatch.setattr(
        auth,
        "parse_args",
        lambda: _namespace(
            agent_id="agent-4",
            ttl=3600,
            json=False,
            base_url=None,
            admin_token=None,
            secret=None,
        ),
    )

    with pytest.raises(SystemExit):
        auth.main()
