"""CLI helper for querying Nimbus log entries."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Query Nimbus logs")
    parser.add_argument("--logs-url", required=True, help="Logging pipeline base URL")
    parser.add_argument("--job-id", type=int, help="Filter logs by job ID")
    parser.add_argument("--contains", help="Substring to search within log messages")
    parser.add_argument("--limit", type=int, default=100, help="Maximum number of entries")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    return parser.parse_args()


async def fetch_logs(base_url: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{base_url.rstrip('/')}/logs/query",
            params=params,
        )
        response.raise_for_status()
        return response.json()


async def run() -> None:
    args = parse_args()
    params: dict[str, Any] = {"limit": args.limit}
    if args.job_id is not None:
        params["job_id"] = args.job_id
    if args.contains:
        params["contains"] = args.contains

    entries = await fetch_logs(args.logs_url, params)
    if args.json:
        print(json.dumps(entries, indent=2))
        return

    if not entries:
        print("No log entries found")
        return

    for entry in entries:
        timestamp = entry.get("timestamp", "-")
        job_id = entry.get("job_id", "-")
        level = entry.get("level", "-")
        message = entry.get("message", "")
        print(f"[{timestamp}] job={job_id} level={level} {message}")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
