from __future__ import annotations

from pathlib import Path

import pytest

from nimbus.common.clickhouse_migrations import ClickHouseMigrationRunner, MigrationResult


class FakeClickHouseClient:
    def __init__(self, applied: list[str] | None = None) -> None:
        self.executed: list[str] = []
        self._applied = applied or []

    def execute(self, sql: str) -> None:
        self.executed.append(sql.strip())

    def select(self, sql: str) -> list[dict[str, object]]:
        if "schema_migrations" in sql:
            return [{"name": name} for name in self._applied]
        return []

    def close(self) -> None:
        pass


def _write_migration(tmp_path: Path, name: str, sql: str) -> Path:
    path = tmp_path / name
    path.write_text(sql, encoding="utf-8")
    return path


def test_clickhouse_migration_runner_applies_new_files(tmp_path: Path) -> None:
    migrations_dir = tmp_path / "clickhouse"
    migrations_dir.mkdir()
    _write_migration(migrations_dir, "001_init.sql", "CREATE TABLE example (id UInt8) ENGINE=Log;")
    client = FakeClickHouseClient()
    runner = ClickHouseMigrationRunner(
        database="nimbus",
        migrations_path=migrations_dir,
        client=client,
    )

    result: MigrationResult = runner.run()

    assert result.applied == ["001_init.sql"]
    assert any("CREATE DATABASE" in statement for statement in client.executed)
    assert any("CREATE TABLE IF NOT EXISTS nimbus.schema_migrations" in stmt or "schema_migrations" in stmt for stmt in client.executed)
    assert any("CREATE TABLE example" in statement for statement in client.executed)
    assert any("INSERT INTO nimbus.schema_migrations" in statement for statement in client.executed)


def test_clickhouse_migration_runner_skips_applied(tmp_path: Path) -> None:
    migrations_dir = tmp_path / "clickhouse"
    migrations_dir.mkdir()
    _write_migration(migrations_dir, "001_init.sql", "CREATE TABLE example (id UInt8) ENGINE=Log;")
    client = FakeClickHouseClient(applied=["001_init.sql"])
    runner = ClickHouseMigrationRunner(
        database="nimbus",
        migrations_path=migrations_dir,
        client=client,
    )

    result = runner.run()

    assert result.applied == []
    # Should still ensure database/table exist
    assert any("CREATE DATABASE" in statement for statement in client.executed)


def test_clickhouse_migration_runner_requires_directory(tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing"
    client = FakeClickHouseClient()
    runner = ClickHouseMigrationRunner(
        database="nimbus",
        migrations_path=missing_dir,
        client=client,
    )

    with pytest.raises(FileNotFoundError):
        runner.run()
