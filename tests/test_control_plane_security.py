from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict

import pytest
from fastapi import HTTPException
from fastapi import FastAPI
from starlette.requests import Request

from nimbus.common.security import mint_agent_token
from nimbus.control_plane.app import AppState, RateLimiter, verify_admin_token, _validate_webhook_timestamp


def make_settings(**overrides: Any):
    base: Dict[str, Any] = {
        "jwt_secret": "jwt-secret",
        "admin_allowed_subjects": ["admin"],
        "admin_allowed_ips": [],
        "admin_rate_limit": 60,
        "admin_rate_interval_seconds": 60,
        "require_https": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


async def make_request(settings, *, headers: Dict[str, str] | None = None, scheme: str = "https", client_ip: str = "203.0.113.10", state: AppState | None = None) -> Request:
    app = FastAPI()
    token = mint_agent_token(agent_id="admin", secret=settings.jwt_secret, ttl_seconds=60)
    raw_headers = [(b"authorization", f"Bearer {token}".encode())]
    if headers:
        raw_headers.extend((key.encode().lower(), value.encode()) for key, value in headers.items())
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/agents",
        "headers": raw_headers,
        "scheme": scheme,
        "client": (client_ip, 12345),
        "server": ("testserver", 80),
        "http_version": "1.1",
        "app": app,
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    if state is None:
        state = AppState(
            settings=settings,
            redis=None,  # type: ignore[arg-type]
            http_client=None,  # type: ignore[arg-type]
            github_client=None,  # type: ignore[arg-type]
            session_factory=None,
            token_rate_limiter=RateLimiter(limit=100, interval=60),
            admin_rate_limiter=RateLimiter(limit=settings.admin_rate_limit, interval=settings.admin_rate_interval_seconds),
        )
    app.state.container = state
    return Request(scope, receive=receive)


@pytest.mark.asyncio
async def test_verify_admin_token_requires_https():
    settings = make_settings(require_https=True, admin_allowed_ips=[])
    request = await make_request(settings, scheme="http")
    with pytest.raises(HTTPException) as excinfo:
        verify_admin_token(request, settings)
    assert excinfo.value.status_code == 400


@pytest.mark.asyncio
async def test_verify_admin_token_blocks_disallowed_ip():
    settings = make_settings(admin_allowed_ips=["203.0.113.5"], require_https=False)
    request = await make_request(settings, scheme="https", client_ip="203.0.113.10")
    with pytest.raises(HTTPException) as excinfo:
        verify_admin_token(request, settings)
    assert excinfo.value.status_code == 403


@pytest.mark.asyncio
async def test_verify_admin_token_rate_limits_subject():
    settings = make_settings(admin_rate_limit=1, admin_rate_interval_seconds=60, require_https=False)
    request1 = await make_request(settings)
    assert verify_admin_token(request1, settings) == "admin"
    state = request1.app.state.container  # type: ignore[attr-defined]
    request2 = await make_request(settings, state=state)
    with pytest.raises(HTTPException) as excinfo:
        verify_admin_token(request2, settings)
    assert excinfo.value.status_code == 429


def test_validate_webhook_timestamp_within_tolerance():
    now = 1_000
    assert _validate_webhook_timestamp(str(now - 30), 60, now=now) == now - 30


def test_validate_webhook_timestamp_tolerance_zero_allows_skew():
    now = 1_000
    assert _validate_webhook_timestamp(str(now - 300), 0, now=now) == now - 300


def test_validate_webhook_timestamp_missing_header():
    with pytest.raises(HTTPException) as excinfo:
        _validate_webhook_timestamp("", 300, now=1_000)
    assert excinfo.value.status_code == 400


def test_validate_webhook_timestamp_invalid_value():
    with pytest.raises(HTTPException) as excinfo:
        _validate_webhook_timestamp("not-an-int", 300, now=1_000)
    assert excinfo.value.status_code == 400


def test_validate_webhook_timestamp_outside_tolerance():
    with pytest.raises(HTTPException) as excinfo:
        _validate_webhook_timestamp(str(1_000), 30, now=1_200)
    assert excinfo.value.status_code == 409
