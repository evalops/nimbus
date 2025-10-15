"""Security utilities shared across Nimbus services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import time

import jwt

from .schemas import CacheToken


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def mint_cache_token(
    *,
    secret: str,
    organization_id: int,
    ttl_seconds: int,
    scope: str = "read_write",
) -> CacheToken:
    expires_at = _utc_now() + timedelta(seconds=ttl_seconds)
    payload = {
        "organization_id": organization_id,
        "expires_at": expires_at.isoformat(),
        "scope": scope,
    }
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), serialized, hashlib.sha256).hexdigest()
    token = _encode(serialized, signature)
    return CacheToken(
        token=token,
        organization_id=organization_id,
        expires_at=expires_at,
        scope=scope,
    )


def verify_cache_token(secret: str, token: str) -> Optional[CacheToken]:
    try:
        encoded_payload, provided_signature = token.split(".", 1)
    except ValueError:
        return None

    try:
        payload_bytes = _decode_payload(encoded_payload)
    except ValueError:
        return None

    expected_signature = hmac.new(
        secret.encode("utf-8"), payload_bytes, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(provided_signature, expected_signature):
        return None

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
        expires_at = datetime.fromisoformat(payload["expires_at"])
    except (ValueError, KeyError):
        return None

    if expires_at <= _utc_now():
        return None

    return CacheToken(
        token=token,
        organization_id=int(payload["organization_id"]),
        expires_at=expires_at,
        scope=payload.get("scope", "read_write"),
    )


def mint_agent_token(
    *, agent_id: str, secret: str, ttl_seconds: int = 3600, version: int = 1
) -> str:
    now = int(time.time())
    payload = {
        "sub": agent_id,
        "iat": now,
        "exp": now + ttl_seconds,
        "ver": version,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_agent_token(secret: str, token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str):
        return None
    return subject


def decode_agent_token_payload(secret: str, token: str) -> Optional[Tuple[str, int]]:
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str):
        return None
    version = payload.get("ver")
    if isinstance(version, int):
        return subject, version
    if isinstance(version, str) and version.isdigit():
        return subject, int(version)
    return subject, 0


def _encode(payload: bytes, signature: str) -> str:
    encoded = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    return f"{encoded}.{signature}"


def _decode_payload(encoded_payload: str) -> bytes:
    padding = "=" * (-len(encoded_payload) % 4)
    return base64.urlsafe_b64decode(encoded_payload + padding)
