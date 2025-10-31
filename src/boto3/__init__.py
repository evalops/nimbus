"""Minimal boto3 stub for local testing without the real dependency."""

from __future__ import annotations

from .session import Session
from . import session as session  # re-export module for compatibility

__all__ = ["client", "resource", "session", "Session"]

_default_session: Session | None = None


def _get_default_session() -> Session:
    global _default_session
    if _default_session is None:
        _default_session = Session()
    return _default_session


def client(*args, **kwargs):  # pragma: no cover - simple pass-through
    return _get_default_session().client(*args, **kwargs)


def resource(*_args, **_kwargs):  # pragma: no cover - currently unused
    raise NotImplementedError("boto3.resource stub is not implemented")
