"""CLI for minting Smith agent tokens."""

from __future__ import annotations

import argparse
import json

import httpx

from ..common.security import mint_agent_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mint Smith agent authentication tokens")
    parser.add_argument("--agent-id", required=True, help="Agent identifier (sub)")
    parser.add_argument("--secret", help="Shared signing secret (omit when using --base-url)")
    parser.add_argument("--ttl", type=int, default=3600, help="Token TTL in seconds")
    parser.add_argument("--json", action="store_true", help="Output JSON structure")
    parser.add_argument("--base-url", help="Control plane base URL to request a token from")
    parser.add_argument(
        "--admin-token",
        help="JWT used to authenticate against the control plane when --base-url is provided",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.base_url:
        if not args.admin_token:
            raise SystemExit("--admin-token is required when --base-url is specified")
        url = args.base_url.rstrip("/") + "/api/agents/token"
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {args.admin_token}"},
            json={"agent_id": args.agent_id, "ttl_seconds": args.ttl},
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
        token = payload["token"]
        ttl = payload.get("ttl_seconds", args.ttl)
    else:
        if not args.secret:
            raise SystemExit("--secret is required when --base-url is not provided")
        token = mint_agent_token(agent_id=args.agent_id, secret=args.secret, ttl_seconds=args.ttl)
        ttl = args.ttl
    if args.json:
        print(
            json.dumps(
                {
                    "agent_id": args.agent_id,
                    "token": token,
                    "ttl_seconds": ttl,
                },
                indent=2,
            )
        )
    else:
        print(token)


if __name__ == "__main__":
    main()
