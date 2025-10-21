"""Utilities for applying ClickHouse schema migrations."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import httpx
import structlog


LOGGER = structlog.get_logger("nimbus.clickhouse.migrations")


class ClickHouseExecutionError(RuntimeError):
    """Raised when a ClickHouse query fails."""


@dataclass(slots=True)
class MigrationResult:
    """Summary of applied migrations."""

    applied: list[str]


class HTTPClickHouseClient:
    """Minimal HTTP client wrapper for ClickHouse queries."""

    def __init__(
        self,
        *,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        auth = httpx.BasicAuth(username, password) if username and password else None
        self._client = httpx.Client(base_url=base_url, auth=auth, timeout=timeout)

    def execute(self, sql: str) -> None:
        response = self._client.post("/", params={"query": sql})
        if response.is_error:
            raise ClickHouseExecutionError(
                f"ClickHouse query failed ({response.status_code}): {response.text[:512]}"
            )

    def select(self, sql: str) -> list[dict[str, object]]:
        response = self._client.get("/", params={"query": f"{sql} FORMAT JSON"})
        if response.is_error:
            raise ClickHouseExecutionError(
                f"ClickHouse select failed ({response.status_code}): {response.text[:512]}"
            )
        payload = response.json()
        return list(payload.get("data", []))

    def close(self) -> None:
        self._client.close()


class ClickHouseMigrationRunner:
    """Apply SQL migrations to a ClickHouse instance in order."""

    def __init__(
        self,
        *,
        database: str,
        migrations_path: Path,
        client: Optional[HTTPClickHouseClient] = None,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self._database = database
        self._migrations_path = migrations_path
        self._owns_client = False
        if client is not None:
            self._client = client
        else:
            if base_url is None:
                raise ValueError("base_url is required when client is not provided")
            self._client = HTTPClickHouseClient(
                base_url=base_url,
                username=username,
                password=password,
                timeout=timeout,
            )
            self._owns_client = True

    def run(self) -> MigrationResult:
        """Apply any pending migrations and return the list applied."""
        try:
            self._ensure_migration_table()
            applied = set(self._fetch_applied_migrations())
            planned = self._discover_migrations()
            new_migrations: list[str] = []
            for migration in planned:
                if migration.name in applied:
                    LOGGER.debug("Migration already applied", migration=migration.name)
                    continue
                LOGGER.info("Applying ClickHouse migration", migration=migration.name)
                sql = migration.read_text(encoding="utf-8")
                self._apply_sql(sql)
                self._record_migration(migration.name)
                new_migrations.append(migration.name)
            return MigrationResult(applied=new_migrations)
        finally:
            if self._owns_client:
                with contextlib.suppress(Exception):
                    self._client.close()

    def _ensure_migration_table(self) -> None:
        stmt = f"CREATE DATABASE IF NOT EXISTS {self._database}"
        self._client.execute(stmt)
        table_stmt = f"""
        CREATE TABLE IF NOT EXISTS {self._database}.schema_migrations (
            name String,
            applied_at DateTime('UTC')
        )
        ENGINE = MergeTree()
        ORDER BY (applied_at, name)
        """
        self._client.execute(table_stmt)

    def _fetch_applied_migrations(self) -> Iterable[str]:
        rows = self._client.select(f"SELECT name FROM {self._database}.schema_migrations")
        for row in rows:
            name = row.get("name")
            if isinstance(name, str):
                yield name

    def _discover_migrations(self) -> list[Path]:
        if not self._migrations_path.exists():
            raise FileNotFoundError(f"ClickHouse migrations directory {self._migrations_path} not found")
        candidates = sorted(self._migrations_path.glob("*.sql"))
        return candidates

    def _apply_sql(self, sql: str) -> None:
        payload = f"USE {self._database};\n{sql}"
        self._client.execute(payload)

    def _record_migration(self, name: str) -> None:
        safe_name = name.replace("'", "''")
        insert = (
            f"INSERT INTO {self._database}.schema_migrations (name, applied_at) "
            f"VALUES ('{safe_name}', now('UTC'))"
        )
        self._client.execute(insert)


def apply_migrations(
    *,
    base_url: str,
    database: str,
    migrations_path: Path,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 10.0,
) -> MigrationResult:
    """Convenience helper to apply migrations without managing the runner directly."""
    runner = ClickHouseMigrationRunner(
        base_url=base_url,
        database=database,
        migrations_path=migrations_path,
        username=username,
        password=password,
        timeout=timeout,
    )
    return runner.run()
