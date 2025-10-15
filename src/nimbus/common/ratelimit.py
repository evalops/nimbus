"""Distributed rate limiting backed by Redis."""

from __future__ import annotations

import time
from typing import Optional

from redis.asyncio import Redis
import structlog

LOGGER = structlog.get_logger("nimbus.ratelimit")


class RateLimiter:
    """Redis-backed distributed rate limiter using token bucket algorithm."""

    def __init__(self, redis: Redis):
        self._redis = redis

    async def check_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Check if a request is within rate limit.
        
        Args:
            key: Unique key for the limit (e.g., "org:123" or "admin:user@example.com")
            limit: Maximum requests allowed in the window
            window_seconds: Time window in seconds
            
        Returns:
            (allowed, current_count) - True if within limit, current request count
        """
        rate_key = f"ratelimit:{key}"
        
        try:
            # Increment counter
            current = await self._redis.incr(rate_key)
            
            # Set expiry on first request in window
            if current == 1:
                await self._redis.expire(rate_key, window_seconds)
            
            # Check if over limit
            allowed = current <= limit
            
            if not allowed:
                LOGGER.warning(
                    "Rate limit exceeded",
                    key=key,
                    current=current,
                    limit=limit,
                    window=window_seconds,
                )
            
            return allowed, current
            
        except Exception as exc:
            # Fail open on Redis errors to avoid cascading failures
            LOGGER.error("Rate limiter error, failing open", key=key, error=str(exc))
            return True, 0

    async def reset(self, key: str) -> None:
        """Reset rate limit counter for a key."""
        rate_key = f"ratelimit:{key}"
        await self._redis.delete(rate_key)


class InMemoryRateLimiter:
    """Fallback in-memory rate limiter (per-process only)."""

    def __init__(self):
        self._counters: dict[str, tuple[int, float]] = {}

    async def check_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """Check rate limit using in-memory counter."""
        now = time.time()
        
        if key in self._counters:
            count, expires_at = self._counters[key]
            if now < expires_at:
                count += 1
                self._counters[key] = (count, expires_at)
            else:
                # Window expired, reset
                count = 1
                self._counters[key] = (count, now + window_seconds)
        else:
            count = 1
            self._counters[key] = (count, now + window_seconds)
        
        allowed = count <= limit
        
        if not allowed:
            LOGGER.warning(
                "Rate limit exceeded (in-memory)",
                key=key,
                current=count,
                limit=limit,
            )
        
        return allowed, count

    async def reset(self, key: str) -> None:
        """Reset rate limit counter."""
        self._counters.pop(key, None)
