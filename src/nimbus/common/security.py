"""Security utilities shared across Nimbus services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import time

import jwt

from .schemas import CacheToken
def key_id_from_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def mint_cache_token(
    *,
    secret: str,
    organization_id: int,
    ttl_seconds: int,
    scope: Optional[str] = None,
) -> CacheToken:
    """
    Mint a cache token with org-scoped permissions.
    
    Args:
        secret: HMAC secret
        organization_id: Organization ID
        ttl_seconds: TTL in seconds
        scope: Scope string like "pull:org-123,push:org-123" or None for full access
    """
    expires_at = _utc_now() + timedelta(seconds=ttl_seconds)
    
    # Default scope preserves legacy behavior permitting full access
    if scope is None:
        scope = "read_write"
    
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
    *, agent_id: str, secret: str, ttl_seconds: int = 3600, version: int = 1, key_id: Optional[str] = None
) -> str:
    now = int(time.time())
    payload = {
        "sub": agent_id,
        "iat": now,
        "exp": now + ttl_seconds,
        "ver": version,
    }
    headers = {"kid": key_id or key_id_from_secret(secret)}
    return jwt.encode(payload, secret, algorithm="HS256", headers=headers)


def decode_agent_token(secret: str, token: str) -> Optional[str]:
    result = decode_agent_token_payload([secret], token)
    if result is None:
        return None
    subject, _ = result
    return subject


def _decode_agent_token_with_secret(secret: str, token: str) -> Optional[Tuple[str, int]]:
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


def decode_agent_token_payload(
    secrets: str | Sequence[str], token: str
) -> Optional[Tuple[str, int]]:
    secret_list: list[str]
    if isinstance(secrets, str):
        secret_list = [secrets]
    else:
        secret_list = list(secrets)
    if not secret_list:
        return None

    preferred: list[str] = secret_list
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
    except jwt.PyJWTError:
        kid = None

    if kid:
        keyed = [secret for secret in secret_list if key_id_from_secret(secret) == kid]
        if keyed:
            preferred = keyed + [secret for secret in secret_list if secret not in keyed]

    for secret in preferred:
        result = _decode_agent_token_with_secret(secret, token)
        if result is not None:
            return result
    return None


def _encode(payload: bytes, signature: str) -> str:
    encoded = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    return f"{encoded}.{signature}"


def _decode_payload(encoded_payload: str) -> bytes:
    padding = "=" * (-len(encoded_payload) % 4)
    return base64.urlsafe_b64decode(encoded_payload + padding)


def validate_cache_scope(token: CacheToken, operation: str, org_id: int, *, repo: Optional[str] = None) -> bool:
    """Check if a cache token has the required scope for an operation on an org."""

    if token.organization_id != org_id:
        return False

    scopes = [s.strip() for s in token.scope.split(",") if s.strip()]
    sanitized_repo = repo.strip("/") if repo else None
    required_repo_scope = (
        f"{operation}:org-{org_id}/{sanitized_repo}"
        if sanitized_repo
        else None
    )

    if required_repo_scope and required_repo_scope in scopes:
        return True

    if token.scope == "read_write":
        return True
    if token.scope == "read" and operation == "pull":
        return True
    if token.scope == "write" and operation == "push":
        return True

    required_scope = f"{operation}:org-{org_id}"
    if required_scope in scopes:
        return True

    if required_repo_scope:
        return required_repo_scope in scopes

    return False


def mint_ssh_token(*, secret: str, job_id: int, session_id: str, ttl_seconds: int) -> str:
    """Mint a short-lived SSH debugging token."""

    expires_at = _utc_now() + timedelta(seconds=ttl_seconds)
    payload = {
        "job_id": job_id,
        "session_id": session_id,
        "expires_at": expires_at.isoformat(),
    }
    serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), serialized, hashlib.sha256).hexdigest()
    return _encode(serialized, signature)


def verify_ssh_token(secret: str, token: str) -> Optional[dict[str, object]]:
    try:
        encoded_payload, provided_signature = token.split(".", 1)
    except ValueError:
        return None

    try:
        payload_bytes = _decode_payload(encoded_payload)
    except ValueError:
        return None

    expected_signature = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided_signature, expected_signature):
        return None

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
        expires_at = datetime.fromisoformat(payload["expires_at"])
    except (ValueError, KeyError):
        return None

    if expires_at <= _utc_now():
        return None

    return {
        "job_id": int(payload.get("job_id", 0)),
        "session_id": str(payload.get("session_id")),
        "expires_at": expires_at,
    }
