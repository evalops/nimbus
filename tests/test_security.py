"""Tests for Nimbus security helpers."""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI, HTTPException
from fastapi import Request

from nimbus.common.http_security import require_metrics_access
from nimbus.common.security import (
    decode_agent_token,
    decode_agent_token_payload,
    mint_agent_token,
    mint_cache_token,
    verify_cache_token,
)


def _make_request(*, headers: dict[str, str] | None = None, client_host: str = "127.0.0.1") -> Request:
    app = FastAPI()
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/metrics",
        "headers": [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()],
        "client": (client_host, 12345),
        "server": ("testserver", 80),
        "http_version": "1.1",
        "scheme": "http",
        "app": app,
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive=receive)


def test_mint_and_verify_cache_token_roundtrip() -> None:
    secret = "super-secret"
    token = mint_cache_token(secret=secret, organization_id=42, ttl_seconds=120)

    decoded = verify_cache_token(secret, token.token)
    assert decoded is not None
    assert decoded.organization_id == 42
    assert decoded.scope == "read_write"


def test_verify_cache_token_expired() -> None:
    secret = "another-secret"
    token = mint_cache_token(secret=secret, organization_id=7, ttl_seconds=-1)
    invalid = verify_cache_token(secret, token.token)
    assert invalid is None


def test_verify_cache_token_wrong_secret() -> None:
    token = mint_cache_token(secret="first", organization_id=1, ttl_seconds=60)
    assert verify_cache_token("second", token.token) is None


def test_agent_token_roundtrip() -> None:
    secret = "agent-secret"
    token = mint_agent_token(agent_id="agent-1", secret=secret, ttl_seconds=60, version=3)
    subject = decode_agent_token(secret, token)
    assert subject == "agent-1"
    payload = decode_agent_token_payload(secret, token)
    assert payload == ("agent-1", 3)


def test_agent_token_invalid_secret() -> None:
    token = mint_agent_token(agent_id="agent-2", secret="alpha", ttl_seconds=60)
    assert decode_agent_token("beta", token) is None


def test_agent_token_expired() -> None:
    secret = "expiring"
    token = mint_agent_token(agent_id="agent-3", secret=secret, ttl_seconds=1)
    time.sleep(2)
    assert decode_agent_token(secret, token) is None


def test_agent_token_rotation_with_key_id() -> None:
    primary = "primary-secret"
    fallback = "fallback-secret"
    token = mint_agent_token(agent_id="runner", secret=primary, ttl_seconds=60, version=2)
    decoded = decode_agent_token_payload([fallback, primary], token)
    assert decoded == ("runner", 2)
    assert decode_agent_token_payload([fallback], token) is None


def test_require_metrics_access_with_valid_token() -> None:
    request = _make_request(headers={"Authorization": "Bearer secret"}, client_host="203.0.113.5")
    require_metrics_access(request, "secret")


def test_require_metrics_access_rejects_invalid_token() -> None:
    request = _make_request(headers={"Authorization": "Bearer wrong"}, client_host="203.0.113.5")
    with pytest.raises(HTTPException) as excinfo:
        require_metrics_access(request, "secret")
    assert excinfo.value.status_code == 401


def test_require_metrics_access_allows_loopback_without_token() -> None:
    request = _make_request(client_host="127.0.0.1")
    require_metrics_access(request, None)


def test_require_metrics_access_blocks_remote_without_token() -> None:
    request = _make_request(client_host="198.51.100.8")
    with pytest.raises(HTTPException) as excinfo:
        require_metrics_access(request, None)
    assert excinfo.value.status_code == 403
