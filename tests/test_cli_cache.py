from __future__ import annotations

from dataclasses import dataclass

from nimbus.cli import cache


@dataclass
class DummyCacheToken:
    token: str
    organization_id: int
    expires_at: "DummyExpiry"
    scope: str


class DummyExpiry:
    def __init__(self, value: str) -> None:
        self._value = value

    def isoformat(self) -> str:
        return self._value


def test_cli_cache_main_json(monkeypatch, capsys, cache_cli_runner):
    cache_cli_runner(org_id=42, ttl=600, scope="read", json=True)
    token = DummyCacheToken("token-1", 42, DummyExpiry("2024"), "read")
    monkeypatch.setattr(cache, "mint_cache_token", lambda **_: token)

    cache.main()
    output = capsys.readouterr().out
    assert "\"token\": \"token-1\"" in output
    assert "\"organization_id\": 42" in output


def test_cli_cache_main_text(monkeypatch, capsys, cache_cli_runner):
    cache_cli_runner(org_id=7, ttl=1200, scope="read_write", json=False)
    token = DummyCacheToken("token-xyz", 7, DummyExpiry("2025"), "read_write")
    monkeypatch.setattr(cache, "mint_cache_token", lambda **_: token)

    cache.main()
    output = capsys.readouterr().out
    assert "Token: token-xyz" in output
    assert "Organization ID: 7" in output
