from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from nimbus.common import ratelimit


class DummyLogger:
    def __init__(self) -> None:
        self.warning_calls: list[tuple[tuple, dict]] = []
        self.error_calls: list[tuple[tuple, dict]] = []

    def warning(self, *args, **kwargs) -> None:  # noqa: ANN001
        self.warning_calls.append((args, kwargs))

    def error(self, *args, **kwargs) -> None:  # noqa: ANN001
        self.error_calls.append((args, kwargs))

    def info(self, *args, **kwargs) -> None:  # noqa: ANN001
        return None

    def debug(self, *args, **kwargs) -> None:  # noqa: ANN001
        return None


@pytest.mark.asyncio
async def test_rate_limiter_allows_within_limit(monkeypatch):
    redis = AsyncMock()
    redis.incr = AsyncMock(return_value=1)
    redis.expire = AsyncMock(return_value=True)

    limiter = ratelimit.RateLimiter(redis)
    allowed, current = await limiter.check_limit("org-1", limit=5, window_seconds=60)

    assert allowed is True
    assert current == 1
    redis.expire.assert_awaited_once()


@pytest.mark.asyncio
async def test_rate_limiter_blocks_when_exceeding(monkeypatch):
    redis = AsyncMock()
    redis.incr = AsyncMock(return_value=6)
    redis.expire = AsyncMock(return_value=True)

    logger = DummyLogger()
    monkeypatch.setattr(ratelimit, "LOGGER", logger)

    limiter = ratelimit.RateLimiter(redis)
    allowed, current = await limiter.check_limit("org-2", limit=5, window_seconds=60)

    assert allowed is False
    assert current == 6
    assert logger.warning_calls, "Expected warning when limit exceeded"


@pytest.mark.asyncio
async def test_rate_limiter_fails_open_on_error(monkeypatch):
    redis = AsyncMock()
    redis.incr = AsyncMock(side_effect=RuntimeError("redis down"))

    logger = DummyLogger()
    monkeypatch.setattr(ratelimit, "LOGGER", logger)

    limiter = ratelimit.RateLimiter(redis)
    allowed, current = await limiter.check_limit("org-3", limit=1, window_seconds=10)

    assert allowed is True
    assert current == 0
    assert logger.error_calls, "Expected error log when redis fails"


@pytest.mark.asyncio
async def test_rate_limiter_reset(monkeypatch):
    redis = AsyncMock()
    limiter = ratelimit.RateLimiter(redis)
    await limiter.reset("org-4")
    redis.delete.assert_awaited_once_with("ratelimit:org-4")


@pytest.mark.asyncio
async def test_inmemory_rate_limiter(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr(ratelimit, "LOGGER", logger)

    limiter = ratelimit.InMemoryRateLimiter()

    allowed1, count1 = await limiter.check_limit("agent-1", limit=2, window_seconds=60)
    allowed2, count2 = await limiter.check_limit("agent-1", limit=2, window_seconds=60)
    allowed3, count3 = await limiter.check_limit("agent-1", limit=2, window_seconds=60)

    assert allowed1 is True and count1 == 1
    assert allowed2 is True and count2 == 2
    assert allowed3 is False and count3 == 3
    assert logger.warning_calls, "Expected warning when in-memory limit exceeded"

    await limiter.reset("agent-1")
    allowed_after_reset, count_after_reset = await limiter.check_limit("agent-1", limit=1, window_seconds=60)
    assert allowed_after_reset is True and count_after_reset == 1
