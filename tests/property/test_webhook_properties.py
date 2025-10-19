"""Property-based tests for webhook timestamp validation."""

from __future__ import annotations

import pytest
from fastapi import HTTPException, status
from hypothesis import given, strategies as st
from hypothesis.strategies import composite

from src.nimbus.control_plane.app import _validate_webhook_timestamp


@composite
def timestamps_within_tolerance(draw):
    tolerance = draw(st.integers(min_value=0, max_value=3600))
    timestamp = draw(st.integers(min_value=0, max_value=2**31))
    offset = draw(st.integers(min_value=-tolerance, max_value=tolerance))
    now = timestamp + offset
    return str(timestamp), tolerance, now


@composite
def timestamps_outside_tolerance(draw):
    tolerance = draw(st.integers(min_value=1, max_value=3600))
    timestamp = draw(st.integers(min_value=0, max_value=2**31))
    delta = draw(st.integers(min_value=tolerance + 1, max_value=tolerance + 3600))
    sign = draw(st.sampled_from((-1, 1)))
    now = timestamp + sign * delta
    return str(timestamp), tolerance, now


@given(timestamps_within_tolerance())
def test_webhook_timestamp_within_tolerance(data):
    raw_timestamp, tolerance, now = data
    result = _validate_webhook_timestamp(raw_timestamp, tolerance, now=now)
    assert result == int(raw_timestamp)


@given(timestamps_outside_tolerance())
def test_webhook_timestamp_outside_tolerance(data):
    raw_timestamp, tolerance, now = data
    with pytest.raises(HTTPException) as exc_info:
        _validate_webhook_timestamp(raw_timestamp, tolerance, now=now)
    assert exc_info.value.status_code == status.HTTP_409_CONFLICT


@given(st.text(min_size=1).filter(lambda s: not s.isdigit()))
def test_webhook_timestamp_rejects_non_numeric(raw_timestamp):
    with pytest.raises(HTTPException) as exc_info:
        _validate_webhook_timestamp(raw_timestamp, tolerance_seconds=300, now=0)
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
