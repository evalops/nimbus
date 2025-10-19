"""Property-based tests for cache proxy key sanitization."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException, status
from hypothesis import given, strategies as st

from src.nimbus.cache_proxy.app import sanitize_key


@given(st.text(min_size=1, max_size=64, alphabet=st.characters(min_codepoint=33, max_codepoint=126)))
def test_sanitize_key_bounds(cache_key: str) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage_root = Path(tmp_dir)
    try:
        resolved = sanitize_key(storage_root, cache_key)
    except HTTPException as exc:
        assert exc.status_code == status.HTTP_400_BAD_REQUEST
    else:
        assert resolved.resolve().is_relative_to(storage_root.resolve())


@given(st.text(min_size=1, max_size=64).filter(lambda s: "\x00" not in s))
def test_sanitize_key_rejects_parent_escape(cache_key: str) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage_root = Path(tmp_dir)
    evil_key = f"../{cache_key}"
    with pytest.raises(HTTPException) as exc_info:
        sanitize_key(storage_root, evil_key)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
