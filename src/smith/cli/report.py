"""Consolidated reporting CLI for Smith services."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx

from .jobs import fetch_recent_jobs, fetch_status, format_timestamp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Smith operational reports")
    subparsers = parser.add_subparsers(dest="command", required=True)

    jobs_parser = subparsers.add_parser("jobs", help="Summarize control plane job activity")
    jobs_parser.add_argument("--base-url", required=True, help="Control plane base URL")
    jobs_parser.add_argument("--token", required=True, help="Control plane bearer token")
    jobs_parser.add_argument("--limit", type=int, default=50, help="Number of recent jobs to inspect")
    jobs_parser.add_argument("--json", action="store_true", help="Output JSON")

    cache_parser = subparsers.add_parser("cache", help="Summarize cache proxy usage")
    cache_parser.add_argument("--cache-url", required=True, help="Cache proxy base URL")
    cache_parser.add_argument(
        "--cache-token",
        help="Cache bearer token (if the status endpoint is secured)",
    )
    cache_parser.add_argument("--top", type=int, default=5, help="Top cache entries to display")
    cache_parser.add_argument("--json", action="store_true", help="Output JSON")

    logs_parser = subparsers.add_parser("logs", help="Summarize recent log ingestion")
    logs_parser.add_argument("--logs-url", required=True, help="Logging pipeline base URL")
    logs_parser.add_argument("--job-id", type=int, help="Filter logs by job id")
    logs_parser.add_argument("--contains", help="Filter logs containing substring")
    logs_parser.add_argument("--limit", type=int, default=100, help="Number of log entries to inspect")
    logs_parser.add_argument("--json", action="store_true", help="Output JSON")

    overview_parser = subparsers.add_parser("overview", help="Aggregate jobs, cache, and logs reports")
    overview_parser.add_argument("--base-url", required=True, help="Control plane base URL")
    overview_parser.add_argument("--token", required=True, help="Control plane bearer token")
    overview_parser.add_argument("--cache-url", required=True, help="Cache proxy base URL")
    overview_parser.add_argument(
        "--cache-token",
        help="Cache bearer token (if the status endpoint is secured)",
    )
    overview_parser.add_argument("--logs-url", required=True, help="Logging pipeline base URL")
    overview_parser.add_argument("--job-limit", type=int, default=50, help="Recent jobs to inspect")
    overview_parser.add_argument("--log-limit", type=int, default=100, help="Recent logs to inspect")
    overview_parser.add_argument("--json", action="store_true", help="Output JSON")

    tokens_parser = subparsers.add_parser("tokens", help="Enumerate agent token inventory")
    tokens_parser.add_argument("--base-url", required=True, help="Control plane base URL")
    tokens_parser.add_argument("--token", required=True, help="Admin bearer token")
    tokens_parser.add_argument("--json", action="store_true", help="Output JSON")

    return parser.parse_args()


def summarize_jobs(status_payload: dict[str, Any], recent_jobs: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter()
    repo_counts = Counter()
    agent_counts = Counter()
    for job in recent_jobs:
        status_counts[job.get("status", "unknown")] += 1
        repo_counts[job.get("repo_full_name") or "unknown"] += 1
        agent_counts[job.get("agent_id") or "unassigned"] += 1

    timeline = []
    for job in sorted(recent_jobs, key=lambda j: j.get("updated_at") or "", reverse=True)[:10]:
        timeline.append(
            {
                "job_id": job.get("job_id"),
                "status": job.get("status"),
                "agent_id": job.get("agent_id"),
                "updated_at": job.get("updated_at"),
            }
        )

    return {
        "queue_length": status_payload.get("queue_length", 0),
        "jobs_by_status": dict(sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))),
        "control_plane_counts": status_payload.get("jobs_by_status", {}),
        "top_repositories": dict(repo_counts.most_common(5)),
        "top_agents": dict(agent_counts.most_common(5)),
        "recent_timeline": timeline,
    }


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def summarize_cache(status_payload: dict[str, Any], top: int = 5) -> dict[str, Any]:
    all_entries = status_payload.get("top_entries", [])
    entries = all_entries[:top]
    total_hits = sum(entry.get("total_hits", 0) for entry in entries)
    total_misses = sum(entry.get("total_misses", 0) for entry in entries)
    total_bytes = sum(entry.get("total_bytes", 0) for entry in entries)
    total_requests = total_hits + total_misses
    hit_ratio = (total_hits / total_requests) if total_requests else None

    cold_entries = [
        {
            "cache_key": entry.get("cache_key"),
            "last_access": entry.get("last_access"),
            "total_hits": entry.get("total_hits", 0),
            "total_bytes": entry.get("total_bytes", 0),
        }
        for entry in sorted(all_entries, key=lambda e: e.get("last_access") or "")
        if entry.get("total_hits", 0) == 0
    ]
    eviction_candidates = cold_entries[: min(top, len(cold_entries))]

    return {
        "backend": status_payload.get("backend"),
        "storage_path": status_payload.get("storage_path"),
        "bucket": status_payload.get("bucket"),
        "total_entries": status_payload.get("total_entries"),
        "top_entries": entries,
        "top_hits": total_hits,
        "top_misses": total_misses,
        "top_bytes": total_bytes,
        "total_requests": total_requests,
        "hit_ratio": hit_ratio,
        "eviction_candidates": eviction_candidates,
        "stale_entry_count": len(cold_entries),
    }


def summarize_logs(log_entries: list[dict[str, Any]]) -> dict[str, Any]:
    level_counts = Counter()
    job_counts = Counter()
    for entry in log_entries:
        level_counts[entry.get("level", "info")] += 1
        job_counts[entry.get("job_id", "unknown")] += 1

    samples = []
    for entry in log_entries[:5]:
        samples.append(
            {
                "job_id": entry.get("job_id"),
                "level": entry.get("level"),
                "timestamp": entry.get("timestamp"),
                "message": entry.get("message"),
            }
        )

    return {
        "entry_count": len(log_entries),
        "levels": dict(sorted(level_counts.items(), key=lambda item: (-item[1], item[0]))),
        "jobs": dict(job_counts.most_common(5)),
        "samples": samples,
    }


def summarize_agent_tokens(records: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    parsed = []
    latest_dt: datetime | None = None
    for record in records:
        rotated_iso = record.get("rotated_at")
        rotated_dt = _parse_timestamp(rotated_iso)
        ttl = int(record.get("ttl_seconds") or 0)
        age_seconds: int | None = None
        if rotated_dt:
            delta = now - rotated_dt
            age_seconds = int(delta.total_seconds())
            if latest_dt is None or rotated_dt > latest_dt:
                latest_dt = rotated_dt
        parsed.append(
            {
                "agent_id": record.get("agent_id"),
                "token_version": int(record.get("token_version") or 0),
                "rotated_at": rotated_iso,
                "ttl_seconds": ttl,
                "age_seconds": age_seconds,
            }
        )

    parsed.sort(key=lambda entry: entry.get("rotated_at") or "", reverse=True)

    expired_agents = [
        entry["agent_id"]
        for entry in parsed
        if entry.get("age_seconds") is not None
        and entry.get("ttl_seconds")
        and entry["age_seconds"] > entry["ttl_seconds"]
    ]
    expiring_agents = [
        entry["agent_id"]
        for entry in parsed
        if entry.get("age_seconds") is not None
        and entry.get("ttl_seconds")
        and entry["agent_id"] not in expired_agents
        and entry["age_seconds"] >= 0.8 * entry["ttl_seconds"]
    ]

    latest_rotation = latest_dt.isoformat() if latest_dt else None

    return {
        "total_agents": len(parsed),
        "latest_rotation_at": latest_rotation,
        "expired_agents": expired_agents,
        "expiring_agents": expiring_agents,
        "entries": parsed,
    }


async def fetch_cache_status(cache_url: str, token: str | None = None) -> dict[str, Any]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{cache_url.rstrip('/')}/status", headers=headers)
        response.raise_for_status()
        return response.json()


async def fetch_logs(logs_url: str, job_id: int | None, contains: str | None, limit: int) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"limit": limit}
    if job_id is not None:
        params["job_id"] = job_id
    if contains:
        params["contains"] = contains

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{logs_url.rstrip('/')}/logs/query", params=params)
        response.raise_for_status()
        return response.json()


async def fetch_agent_tokens(base_url: str, token: str) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{base_url.rstrip('/')}/api/agents", headers=headers)
        response.raise_for_status()
        return response.json()


def print_job_summary(summary: dict[str, Any]) -> None:
    print(f"Queue length: {summary['queue_length']}")
    cp_counts = summary.get("control_plane_counts", {})
    if cp_counts:
        print("Control plane job counts:")
        for status, count in sorted(cp_counts.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {status}: {count}")

    print("Recent job statuses (top 10):")
    for entry in summary["recent_timeline"]:
        ts = format_timestamp(entry.get("updated_at"))
        print(f"  #{entry['job_id']} {entry['status']} (agent: {entry['agent_id'] or '-'}, updated: {ts})")

    print("Top repositories:")
    for repo, count in summary["top_repositories"].items():
        print(f"  {repo}: {count}")

    print("Top agents:")
    for agent, count in summary["top_agents"].items():
        print(f"  {agent}: {count}")


def print_cache_summary(summary: dict[str, Any]) -> None:
    backend = summary.get("backend") or summary.get("bucket")
    print(f"Backend: {backend}")
    if summary.get("storage_path"):
        print(f"Storage path: {summary['storage_path']}")
    if summary.get("bucket"):
        print(f"Bucket: {summary['bucket']}")
    print(f"Total entries (tracked): {summary.get('total_entries', 'n/a')}")
    print("Top cache keys:")
    entries = summary.get("top_entries", [])
    if entries:
        for entry in entries:
            key = entry.get("cache_key")
            hits = entry.get("total_hits")
            misses = entry.get("total_misses")
            bytes_served = entry.get("total_bytes")
            print(f"  {key}: hits={hits}, misses={misses}, bytes={bytes_served}")
    else:
        print("  (none)")
    ratio = summary.get("hit_ratio")
    if ratio is not None:
        print(f"Hit ratio (top entries): {ratio:.1%}")
    stale_count = summary.get("stale_entry_count", 0)
    print(f"Stale keys (hits=0): {stale_count}")
    print("Eviction candidates:")
    candidates = summary.get("eviction_candidates", [])
    if candidates:
        for entry in candidates:
            last_access = entry.get("last_access") or "unknown"
            print(f"  {entry.get('cache_key')}: last_access={last_access}, size_bytes={entry.get('total_bytes')}")
    else:
        print("  (none)")


def print_log_summary(summary: dict[str, Any]) -> None:
    print(f"Entries analyzed: {summary['entry_count']}")
    print("Levels:")
    for level, count in summary["levels"].items():
        print(f"  {level}: {count}")

    print("Top jobs:")
    if summary["jobs"]:
        for job_id, count in summary["jobs"].items():
            print(f"  {job_id}: {count}")
    else:
        print("  (none)")


def print_token_summary(summary: dict[str, Any]) -> None:
    print(f"Total agents: {summary['total_agents']}")
    latest = summary.get("latest_rotation_at")
    if latest:
        print(f"Latest rotation: {latest}")
    expired = summary.get("expired_agents", [])
    expiring = summary.get("expiring_agents", [])
    print(
        "Expired agents: "
        + (", ".join(expired) if expired else "none")
    )
    if expiring:
        print("Expiring soon: " + ", ".join(expiring))
    print("Agent inventory:")
    entries = summary.get("entries", [])
    if not entries:
        print("  (none)")
        return
    for entry in entries:
        age_seconds = entry.get("age_seconds")
        age_str = f"{age_seconds / 3600:.1f}h" if age_seconds is not None else "unknown"
        ttl = entry.get("ttl_seconds") or 0
        ttl_str = f"{ttl / 3600:.1f}h" if ttl else "n/a"
        print(
            f"  {entry.get('agent_id')}: version={entry.get('token_version')}, rotated={entry.get('rotated_at')}, "
            f"age={age_str}, ttl={ttl_str}"
        )

    print("Sample log entries:")
    if summary["samples"]:
        for sample in summary["samples"]:
            ts = sample.get("timestamp")
            print(f"  [{sample['level']}] job={sample['job_id']} {ts}: {sample['message']}")
    else:
        print("  (none)")


async def run_jobs(args: argparse.Namespace) -> None:
    recent_jobs, status_payload = await asyncio.gather(
        fetch_recent_jobs(args.base_url, args.token, args.limit),
        fetch_status(args.base_url, args.token),
    )
    summary = summarize_jobs(status_payload, recent_jobs)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_job_summary(summary)


async def run_cache(args: argparse.Namespace) -> None:
    status_payload = await fetch_cache_status(args.cache_url, args.cache_token)
    summary = summarize_cache(status_payload, top=args.top)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_cache_summary(summary)


async def run_logs(args: argparse.Namespace) -> None:
    entries = await fetch_logs(args.logs_url, args.job_id, args.contains, args.limit)
    summary = summarize_logs(entries)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_log_summary(summary)


async def run_tokens(args: argparse.Namespace) -> None:
    records = await fetch_agent_tokens(args.base_url, args.token)
    summary = summarize_agent_tokens(records)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_token_summary(summary)


async def run_overview(args: argparse.Namespace) -> None:
    jobs_task = asyncio.create_task(
        asyncio.gather(
            fetch_recent_jobs(args.base_url, args.token, args.job_limit),
            fetch_status(args.base_url, args.token),
        )
    )
    cache_task = asyncio.create_task(fetch_cache_status(args.cache_url, args.cache_token))
    logs_task = asyncio.create_task(fetch_logs(args.logs_url, None, None, args.log_limit))

    recent_jobs, status_payload = await jobs_task
    cache_status = await cache_task
    log_entries = await logs_task

    job_summary = summarize_jobs(status_payload, recent_jobs)
    cache_summary = summarize_cache(cache_status)
    log_summary = summarize_logs(log_entries)
    overview = {
        "jobs": job_summary,
        "cache": cache_summary,
        "logs": log_summary,
    }

    if args.json:
        print(json.dumps(overview, indent=2))
        return

    print("=== Jobs ===")
    print_job_summary(job_summary)
    print("\n=== Cache ===")
    print_cache_summary(cache_summary)
    print("\n=== Logs ===")
    print_log_summary(log_summary)


async def run_async() -> None:
    args = parse_args()
    if args.command == "jobs":
        await run_jobs(args)
    elif args.command == "cache":
        await run_cache(args)
    elif args.command == "logs":
        await run_logs(args)
    elif args.command == "overview":
        await run_overview(args)
    elif args.command == "tokens":
        await run_tokens(args)


def main() -> None:
    asyncio.run(run_async())


if __name__ == "__main__":
    main()
