"""Command-line utilities for inspecting Nimbus jobs."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime
from typing import Any

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect Nimbus job records")
    parser.add_argument("--base-url", required=True, help="Nimbus control plane base URL")
    parser.add_argument("--token", required=True, help="Bearer token for authentication")

    subparsers = parser.add_subparsers(dest="command", required=True)

    recent_parser = subparsers.add_parser("recent", help="List recent jobs")
    recent_parser.add_argument("--limit", type=int, default=20, help="Number of jobs to fetch")
    recent_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    status_parser = subparsers.add_parser("status", help="Show queue depth and job counts")
    status_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    return parser.parse_args()


async def fetch_recent_jobs(base_url: str, token: str, limit: int) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{base_url.rstrip('/')}/api/jobs/recent",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": limit},
        )
        response.raise_for_status()
        return response.json()


async def fetch_status(base_url: str, token: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{base_url.rstrip('/')}/api/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        return response.json()


def format_timestamp(value: str | None) -> str:
    if not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def print_table(rows: list[dict[str, Any]]) -> None:
    headers = ["job_id", "status", "agent_id", "repo", "queued_at", "updated_at"]
    widths = {header: len(header) for header in headers}
    normalized: list[dict[str, str]] = []

    for row in rows:
        normalized_row = {
            "job_id": str(row.get("job_id", "")),
            "status": str(row.get("status", "")),
            "agent_id": row.get("agent_id") or "-",
            "repo": row.get("repo_full_name") or "-",
            "queued_at": format_timestamp(row.get("queued_at")),
            "updated_at": format_timestamp(row.get("updated_at")),
        }
        for key, value in normalized_row.items():
            widths[key] = max(widths[key], len(value))
        normalized.append(normalized_row)

    header_line = "  ".join(key.ljust(widths[key]) for key in headers)
    print(header_line)
    print("  ".join("-" * widths[key] for key in headers))
    for row in normalized:
        print("  ".join(row[key].ljust(widths[key]) for key in headers))


async def run() -> None:
    args = parse_args()
    if args.command == "recent":
        jobs = await fetch_recent_jobs(args.base_url, args.token, args.limit)
        if args.json:
            print(json.dumps(jobs, indent=2))
        else:
            print_table(jobs)
    elif args.command == "status":
        status_payload = await fetch_status(args.base_url, args.token)
        if args.json:
            print(json.dumps(status_payload, indent=2))
        else:
            print(f"Queue length: {status_payload.get('queue_length', 0)}")
            counts = status_payload.get("jobs_by_status", {})
            if counts:
                print("Jobs by status:")
                for key, value in sorted(counts.items()):
                    print(f"  {key}: {value}")
            else:
                print("Jobs by status: none")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
