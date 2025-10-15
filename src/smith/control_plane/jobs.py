"""Job queue abstraction backed by Redis."""

from __future__ import annotations

import json
from typing import Optional

from redis.asyncio import Redis

from ..common.schemas import JobAssignment

QUEUE_KEY = "smith:jobs:queued"


async def enqueue_job(redis: Redis, assignment: JobAssignment) -> None:
    """Push a job assignment onto the queue."""

    await redis.lpush(QUEUE_KEY, assignment.model_dump_json())


async def lease_job(redis: Redis) -> Optional[JobAssignment]:
    """Pop the oldest job assignment from the queue."""

    data = await redis.rpop(QUEUE_KEY)
    if not data:
        return None
    if isinstance(data, bytes):
        payload = data.decode("utf-8")
    else:
        payload = data
    json_payload = json.loads(payload)
    return JobAssignment.model_validate(json_payload)
