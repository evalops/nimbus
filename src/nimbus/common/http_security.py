"""Shared HTTP security helpers."""

from __future__ import annotations

import hmac
from ipaddress import ip_address
from typing import Optional

from fastapi import HTTPException, Request, status


def require_metrics_access(request: Request, token: Optional[str]) -> None:
    """Enforce metrics endpoint authentication via token or localhost constraint."""
    if token:
        expected = f"Bearer {token}"
        auth_header = request.headers.get("authorization")
        if not auth_header or not hmac.compare_digest(auth_header, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid metrics token")
        return

    client = request.client
    client_host = client.host if client else None
    if not client_host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Metrics access denied")

    try:
        if not ip_address(client_host).is_loopback:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Metrics access restricted to localhost",
            )
    except ValueError as exc:  # pragma: no cover - platform dependent
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Metrics access denied") from exc
