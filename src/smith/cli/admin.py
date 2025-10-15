"""Administrative tooling for Smith control plane operations."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

import httpx

from .report import print_token_summary, summarize_agent_tokens


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smith administrative utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("tokens", help="Inspect or rotate agent tokens")
    action_parsers = inventory.add_subparsers(dest="tokens_cmd", required=True)

    list_parser = action_parsers.add_parser("list", help="List agent token metadata")
    list_parser.add_argument("--base-url", required=True, help="Control plane base URL")
    list_parser.add_argument("--admin-token", required=True, help="Admin bearer token")
    list_parser.add_argument("--json", action="store_true", help="Output JSON")
    list_parser.add_argument("--history-limit", type=int, default=0, help="Include recent rotation audit records")

    rotate_parser = action_parsers.add_parser("rotate", help="Rotate an agent token")
    rotate_parser.add_argument("--base-url", required=True, help="Control plane base URL")
    rotate_parser.add_argument("--admin-token", required=True, help="Admin bearer token")
    rotate_parser.add_argument("--agent-id", required=True, help="Agent identifier to rotate")
    rotate_parser.add_argument("--ttl", type=int, default=3600, help="Token TTL in seconds")
    rotate_parser.add_argument("--json", action="store_true", help="Output JSON")

    return parser.parse_args()


async def fetch_token_inventory(base_url: str, admin_token: str) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{base_url.rstrip('/')}/api/agents", headers=headers)
        response.raise_for_status()
        return response.json()


async def fetch_token_audit(base_url: str, admin_token: str, limit: int) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {admin_token}"}
    params = {"limit": limit}
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{base_url.rstrip('/')}/api/agents/audit", headers=headers, params=params)
        response.raise_for_status()
        return response.json()


async def rotate_agent_token(base_url: str, admin_token: str, agent_id: str, ttl: int) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {"agent_id": agent_id, "ttl_seconds": ttl}
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(f"{base_url.rstrip('/')}/api/agents/token", headers=headers, json=payload)
        response.raise_for_status()
        return response.json()


async def run_tokens_list(args: argparse.Namespace) -> None:
    records = await fetch_token_inventory(args.base_url, args.admin_token)
    summary = summarize_agent_tokens(records)
    audit_records: list[dict[str, Any]] = []
    if args.history_limit > 0:
        audit_records = await fetch_token_audit(args.base_url, args.admin_token, args.history_limit)
    if args.json:
        print(json.dumps({"inventory": records, "summary": summary, "audit": audit_records}, indent=2))
    else:
        print_token_summary(summary)
        if audit_records:
            print("\nRecent rotations:")
            for entry in audit_records:
                print(
                    f"  {entry.get('rotated_at')}: agent={entry.get('agent_id')}"
                    f" version={entry.get('token_version')} by={entry.get('rotated_by')}"
                )


async def run_tokens_rotate(args: argparse.Namespace) -> None:
    result = await rotate_agent_token(args.base_url, args.admin_token, args.agent_id, args.ttl)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Rotated token for {result['agent_id']} (version {result['version']})")
    print(f"TTL seconds: {result['ttl_seconds']}")
    print(f"Expires at: {result['expires_at']}")
    print(f"Token: {result['token']}")


async def run_async() -> None:
    args = parse_args()
    if args.command == "tokens" and args.tokens_cmd == "list":
        await run_tokens_list(args)
    elif args.command == "tokens" and args.tokens_cmd == "rotate":
        await run_tokens_rotate(args)


def main() -> None:
    asyncio.run(run_async())


if __name__ == "__main__":
    main()
