"""CLI entrypoint for applying ClickHouse migrations."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from nimbus.common.clickhouse_migrations import apply_migrations


def _default_migrations_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "migrations" / "clickhouse"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply ClickHouse SQL migrations")
    parser.add_argument("--url", dest="url", default=os.getenv("NIMBUS_CLICKHOUSE_URL"), help="ClickHouse HTTP endpoint")
    parser.add_argument("--database", dest="database", default=os.getenv("NIMBUS_CLICKHOUSE_DATABASE", "nimbus"), help="Target ClickHouse database")
    parser.add_argument(
        "--migrations",
        dest="migrations",
        type=Path,
        default=_default_migrations_dir(),
        help="Directory containing *.sql migrations",
    )
    parser.add_argument("--username", dest="username", default=os.getenv("NIMBUS_CLICKHOUSE_USERNAME"))
    parser.add_argument("--password", dest="password", default=os.getenv("NIMBUS_CLICKHOUSE_PASSWORD"))
    parser.add_argument("--timeout", dest="timeout", type=float, default=float(os.getenv("NIMBUS_CLICKHOUSE_TIMEOUT", 10)))
    args = parser.parse_args(argv)

    if not args.url:
        parser.error("ClickHouse URL must be provided via --url or NIMBUS_CLICKHOUSE_URL")

    result = apply_migrations(
        base_url=args.url,
        database=args.database,
        migrations_path=args.migrations,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
    )

    if result.applied:
        for migration in result.applied:
            print(f"applied {migration}")  # noqa: T201 - user-facing CLI output
    else:
        print("no migrations to apply")  # noqa: T201
    return 0


if __name__ == "__main__":  # pragma: no mutate - CLI guard
    sys.exit(main())
