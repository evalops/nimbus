"""Job queue abstraction backed by Redis."""

from __future__ import annotations

import json
from typing import Optional

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from ..common.schemas import JobAssignment
from .db import try_acquire_job_lease, mark_job_leased

QUEUE_KEY = "nimbus:jobs:queued"


async def enqueue_job(redis: Redis, assignment: JobAssignment) -> None:
    """Push a job assignment onto the queue."""

    await redis.lpush(QUEUE_KEY, assignment.model_dump_json())


async def lease_job(redis: Redis) -> Optional[JobAssignment]:
    """Pop the oldest job assignment from the queue (legacy, no fencing)."""

    data = await redis.rpop(QUEUE_KEY)
    if not data:
        return None
    if isinstance(data, bytes):
        payload = data.decode("utf-8")
    else:
        payload = data
    json_payload = json.loads(payload)
    return JobAssignment.model_validate(json_payload)


async def lease_job_with_fence(
    redis: Redis, session: AsyncSession, agent_id: str, ttl_seconds: int
) -> Optional[tuple[JobAssignment, int]]:
    """
    Pop the oldest job from the queue and acquire a DB-backed lease with fence token.
    Returns (assignment, fence_token) on success, None if no work or lease acquisition failed.
    """
    data = await redis.rpop(QUEUE_KEY)
    if not data:
        return None

    if isinstance(data, bytes):
        payload = data.decode("utf-8")
    else:
        payload = data

    json_payload = json.loads(payload)
    assignment = JobAssignment.model_validate(json_payload)

    # Try to acquire DB-backed lease
    fence = await try_acquire_job_lease(session, assignment.job_id, agent_id, ttl_seconds)
    if fence is None:
        # Someone else holds a valid lease; push back to queue to avoid job loss
        await redis.lpush(QUEUE_KEY, payload)
        return None

    # Mark job as leased in jobs table
    await mark_job_leased(session, assignment.job_id, agent_id)
    return assignment, fence
