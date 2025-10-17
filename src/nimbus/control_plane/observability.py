"""Tenant observability aggregations for the Nimbus control plane."""

from __future__ import annotations

from __future__ import annotations

from datetime import datetime
from typing import Iterable


def build_org_overview(
    org_ids: Iterable[int],
    *,
    status_rows: list[dict],
    last_activity: dict[int, datetime],
    active_agents: dict[int, set[str]],
    failures: dict[int, list[dict]],
) -> list[dict]:
    status_map: dict[int, dict[str, int]] = {}
    for row in status_rows:
        org_id = int(row["org_id"])
        status_map.setdefault(org_id, {})[row["status"]] = row["count"]

    summaries: list[dict] = []
    for org_id in org_ids:
        summaries.append(
            {
                "org_id": int(org_id),
                "status_counts": status_map.get(org_id, {}),
                "last_activity": last_activity.get(org_id),
                "active_agents": sorted(active_agents.get(org_id, set())),
                "recent_failures": failures.get(org_id, []),
            }
        )
    return summaries
