from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from nimbus.control_plane import app as control_app


def _make_request(headers: dict[str, str], client_ip: str = "203.0.113.10") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "scheme": "http",
        "client": (client_ip, 12345),
        "headers": [(key.encode("latin-1"), value.encode("latin-1")) for key, value in headers.items()],
    }

    async def receive() -> dict:  # pragma: no cover - protocol shim
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def test_default_cache_scope() -> None:
    assert control_app._default_cache_scope(42) == "pull:org-42,push:org-42"


def test_validate_webhook_timestamp_accepts_current(monkeypatch) -> None:
    now = int(1_700_000_000)
    result = control_app._validate_webhook_timestamp(str(now), tolerance_seconds=30, now=now)
    assert result == now


@pytest.mark.parametrize("value", ["", "not-int"])
def test_validate_webhook_timestamp_rejects_invalid(value: str) -> None:
    with pytest.raises(HTTPException) as exc:
        control_app._validate_webhook_timestamp(value, tolerance_seconds=10)
    assert exc.value.status_code == 400


def test_validate_webhook_timestamp_rejects_stale() -> None:
    now = 1_700_000_000
    with pytest.raises(HTTPException) as exc:
        control_app._validate_webhook_timestamp(str(now - 100), tolerance_seconds=10, now=now)
    assert exc.value.status_code == 409


def test_get_client_ip_without_trusted_proxies() -> None:
    request = _make_request({}, client_ip="198.51.100.7")
    ip = control_app.get_client_ip(request, trusted_proxies=[])
    assert ip == "198.51.100.7"


def test_get_client_ip_with_trusted_proxy() -> None:
    headers = {"x-forwarded-for": "10.0.0.5"}
    request = _make_request(headers, client_ip="192.0.2.1")
    ip = control_app.get_client_ip(request, trusted_proxies=["192.0.2.0/24"])
    assert ip == "10.0.0.5"


def test_get_client_ip_with_untrusted_proxy() -> None:
    headers = {"x-forwarded-for": "10.0.0.5"}
    request = _make_request(headers, client_ip="203.0.113.1")
    ip = control_app.get_client_ip(request, trusted_proxies=["192.0.2.0/24"])
    assert ip == "203.0.113.1"


def test_row_to_ssh_session_parses_strings() -> None:
    row = {
        "session_id": "sess",
        "job_id": 1,
        "agent_id": "agent",
        "host_port": 2222,
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),
        "expires_at": datetime(2024, 1, 1, 1, tzinfo=timezone.utc).isoformat(),
    }
    session = control_app._row_to_ssh_session(row)
    assert session.session_id == "sess"
    assert session.created_at.tzinfo is not None
    assert session.expires_at > session.created_at


def test_rate_limiter_allows_within_limit(monkeypatch) -> None:
    limiter = control_app.RateLimiter(limit=2, interval=1.0)
    times = [0.0, 0.1, 0.2]

    def fake_time() -> float:
        return times.pop(0)

    monkeypatch.setattr(control_app.time, "time", fake_time)
    assert limiter.allow("key") is True
    assert limiter.allow("key") is True
    assert limiter.allow("key") is False


def test_rate_limiter_disabled() -> None:
    limiter = control_app.RateLimiter(limit=0, interval=1.0)
    for _ in range(5):
        assert limiter.allow("key") is True
