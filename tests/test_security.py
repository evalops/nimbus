"""Tests for Smith security helpers."""

from __future__ import annotations

import time

from smith.common.security import (
    decode_agent_token,
    decode_agent_token_payload,
    mint_agent_token,
    mint_cache_token,
    verify_cache_token,
)


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
