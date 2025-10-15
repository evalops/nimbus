"""CLI for minting Smith agent tokens."""

from __future__ import annotations

import argparse
import json

from ..common.security import mint_agent_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mint Smith agent authentication tokens")
    parser.add_argument("--agent-id", required=True, help="Agent identifier (sub)")
    parser.add_argument("--secret", required=True, help="Shared signing secret")
    parser.add_argument("--ttl", type=int, default=3600, help="Token TTL in seconds")
    parser.add_argument("--json", action="store_true", help="Output JSON structure")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    token = mint_agent_token(agent_id=args.agent_id, secret=args.secret, ttl_seconds=args.ttl)
    if args.json:
        print(
            json.dumps(
                {
                    "agent_id": args.agent_id,
                    "token": token,
                    "ttl_seconds": args.ttl,
                },
                indent=2,
            )
        )
    else:
        print(token)


if __name__ == "__main__":
    main()
