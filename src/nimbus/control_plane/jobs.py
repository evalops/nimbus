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
    redis: Redis, session: AsyncSession, agent_id: str, ttl_seconds: int, capabilities: Optional[list[str]] = None
) -> Optional[tuple[JobAssignment, int]]:
    """
    Pop the oldest job from the queue and acquire a DB-backed lease with fence token.
    Returns (assignment, fence_token) on success, None if no work or lease acquisition failed.
    Now supports capability matching - agent must have required executor capability.
    """
    # For simple capability matching, we'll scan the queue for a compatible job
    max_scan = 100  # Limit to avoid blocking too long
    checked_jobs = []
    capabilities = capabilities or []
    
    for _ in range(max_scan):
        data = await redis.rpop(QUEUE_KEY)
        if not data:
            # No more jobs, push back any we couldn't handle
            for job_data in checked_jobs:
                await redis.lpush(QUEUE_KEY, job_data)
            return None

        if isinstance(data, bytes):
            payload = data.decode("utf-8")
        else:
            payload = data

        json_payload = json.loads(payload)
        assignment = JobAssignment.model_validate(json_payload)
        
        # Check if agent can handle this executor
        required_executor = getattr(assignment, 'executor', 'firecracker')
        if required_executor in capabilities or not capabilities:
            # Compatible job found, push back others and continue with this one
            for job_data in checked_jobs:
                await redis.lpush(QUEUE_KEY, job_data)
            break
        else:
            # Can't handle this job, save it and try next
            checked_jobs.append(payload)
            continue
    else:
        # Scanned max jobs without finding compatible one
        for job_data in checked_jobs:
            await redis.lpush(QUEUE_KEY, job_data)
        return None

    # Try to acquire DB-backed lease
    fence = await try_acquire_job_lease(session, assignment.job_id, agent_id, ttl_seconds)
    if fence is None:
        # Someone else holds a valid lease; push back to queue to avoid job loss
        await redis.lpush(QUEUE_KEY, payload)
        return None

    # Mark job as leased in jobs table (only if still queued)
    marked = await mark_job_leased(session, assignment.job_id, agent_id)
    if not marked:
        # Job was already leased or completed; release our lease and push back
        from .db import release_job_lease
        await release_job_lease(session, assignment.job_id, agent_id, fence)
        # Note: Transaction will be rolled back or committed by caller
        await redis.lpush(QUEUE_KEY, payload)
        return None
    
    # Success - transaction will be committed by caller
    return assignment, fence
