"""Tests for Smith security helpers."""

from __future__ import annotations

from smith.common.security import mint_cache_token, verify_cache_token


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
