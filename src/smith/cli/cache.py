"""CLI to mint Smith cache tokens."""

from __future__ import annotations

import argparse
import json

from ..common.security import mint_cache_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mint signed cache tokens")
    parser.add_argument("--secret", required=True, help="Shared cache secret")
    parser.add_argument("--org-id", type=int, required=True, help="Organization identifier")
    parser.add_argument(
        "--ttl", type=int, default=3600, help="Token time-to-live in seconds (default: 3600)"
    )
    parser.add_argument(
        "--scope",
        default="read_write",
        choices=["read", "write", "read_write"],
        help="Cache token scope",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of plain text")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    token = mint_cache_token(
        secret=args.secret,
        organization_id=args.org_id,
        ttl_seconds=args.ttl,
        scope=args.scope,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "token": token.token,
                    "organization_id": token.organization_id,
                    "scope": token.scope,
                    "expires_at": token.expires_at.isoformat(),
                },
                indent=2,
            )
        )
    else:
        print(f"Token: {token.token}")
        print(f"Organization ID: {token.organization_id}")
        print(f"Scope: {token.scope}")
        print(f"Expires At: {token.expires_at.isoformat()}")


if __name__ == "__main__":
    main()
