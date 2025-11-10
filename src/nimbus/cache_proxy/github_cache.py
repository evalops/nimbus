"""GitHub Actions cache compatibility helpers for the Nimbus cache proxy."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from sqlalchemy import Engine, text


@dataclass(slots=True)
class GitHubCacheEntry:
    entry_id: str
    org_id: int
    repository_id: int
    cache_key: str
    version: str
    scope: str
    storage_key: str
    upload_token: str
    download_token: str
    status: str
    size_bytes: int


class GitHubCacheStore:
    """SQL-backed store for GitHub Actions cache reservations."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._initialise()

    def reserve_entry(
        self,
        *,
        org_id: int,
        repository_id: int,
        scopes: Sequence[str],
        cache_key: str,
        version: str,
    ) -> tuple[GitHubCacheEntry, list[GitHubCacheEntry]]:
        entry_id = secrets.token_hex(16)
        upload_token = secrets.token_urlsafe(32)
        download_token = secrets.token_urlsafe(32)
        scope_str = ",".join(sorted({scope for scope in scopes if scope}))
        storage_key = self._build_storage_key(org_id, repository_id, cache_key, version, entry_id)
        sequence_value = time.time()

        evicted: list[GitHubCacheEntry] = []
        with self._engine.begin() as conn:
            existing = conn.execute(
                text(
                    """
                    SELECT entry_id, org_id, repository_id, cache_key, version, scope,
                           storage_key, upload_token, download_token, status, size_bytes
                    FROM github_cache_entries
                    WHERE org_id = :org_id
                      AND repository_id = :repository_id
                      AND cache_key = :cache_key
                      AND version = :version
                    """
                ),
                {
                    "org_id": org_id,
                    "repository_id": repository_id,
                    "cache_key": cache_key,
                    "version": version,
                },
            ).mappings()
            for row in existing:
                evicted.append(self._row_to_entry(row))

            conn.execute(
                text(
                    """
                    DELETE FROM github_cache_entries
                    WHERE org_id = :org_id
                      AND repository_id = :repository_id
                      AND cache_key = :cache_key
                      AND version = :version
                    """
                ),
                {
                    "org_id": org_id,
                    "repository_id": repository_id,
                    "cache_key": cache_key,
                    "version": version,
                },
            )

            conn.execute(
                text(
                    """
                    INSERT INTO github_cache_entries (
                        entry_id, org_id, repository_id, cache_key, version, scope,
                        storage_key, upload_token, download_token, status, size_bytes, sequence
                    ) VALUES (
                        :entry_id, :org_id, :repository_id, :cache_key, :version, :scope,
                        :storage_key, :upload_token, :download_token, :status, :size_bytes, :sequence
                    )
                    """
                ),
                {
                    "entry_id": entry_id,
                    "org_id": org_id,
                    "repository_id": repository_id,
                    "cache_key": cache_key,
                    "version": version,
                    "scope": scope_str,
                    "storage_key": storage_key,
                    "upload_token": upload_token,
                    "download_token": download_token,
                    "status": "reserved",
                    "size_bytes": 0,
                    "sequence": sequence_value,
                },
            )

        entry = GitHubCacheEntry(
            entry_id=entry_id,
            org_id=org_id,
            repository_id=repository_id,
            cache_key=cache_key,
            version=version,
            scope=scope_str,
            storage_key=storage_key,
            upload_token=upload_token,
            download_token=download_token,
            status="reserved",
            size_bytes=0,
        )
        return entry, evicted

    def mark_uploaded(self, entry_id: str, *, size_bytes: int) -> GitHubCacheEntry:
        with self._engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE github_cache_entries
                    SET status = :status,
                        size_bytes = :size_bytes,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE entry_id = :entry_id
                    RETURNING entry_id, org_id, repository_id, cache_key, version, scope,
                              storage_key, upload_token, download_token, status, size_bytes
                    """
                ),
                {
                    "entry_id": entry_id,
                    "size_bytes": size_bytes,
                    "status": "uploaded",
                },
            ).mappings().one_or_none()

        if row is None:
            raise KeyError(f"Cache entry {entry_id} not found for upload")
        return self._row_to_entry(row)

    def mark_committed(
        self,
        *,
        org_id: int,
        repository_id: int,
        cache_key: str,
        version: str,
        expected_size: int,
    ) -> GitHubCacheEntry:
        with self._engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    UPDATE github_cache_entries
                    SET status = :status,
                        sequence = :sequence,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE org_id = :org_id
                      AND repository_id = :repository_id
                      AND cache_key = :cache_key
                      AND version = :version
                    RETURNING entry_id, org_id, repository_id, cache_key, version, scope,
                              storage_key, upload_token, download_token, status, size_bytes
                    """
                ),
                {
                    "status": "committed",
                    "org_id": org_id,
                    "repository_id": repository_id,
                    "cache_key": cache_key,
                    "version": version,
                    "sequence": time.time(),
                },
            ).mappings().one_or_none()

        if row is None:
            raise KeyError("Cache entry not found during finalization")
        entry = self._row_to_entry(row)
        if expected_size and entry.size_bytes != expected_size:
            raise ValueError(
                f"Size mismatch for cache entry {entry.entry_id}: "
                f"expected {expected_size}, got {entry.size_bytes}"
            )
        return entry

    def find_for_download(
        self,
        *,
        org_id: int,
        repository_id: int,
        cache_key: str,
        version: str,
        restore_keys: Sequence[str],
    ) -> GitHubCacheEntry | None:
        with self._engine.connect() as conn:
            exact = conn.execute(
                text(
                    """
                    SELECT entry_id, org_id, repository_id, cache_key, version, scope,
                           storage_key, upload_token, download_token, status, size_bytes
                    FROM github_cache_entries
                    WHERE org_id = :org_id
                      AND repository_id = :repository_id
                      AND cache_key = :cache_key
                      AND version = :version
                      AND status = 'committed'
                    ORDER BY sequence DESC, updated_at DESC, created_at DESC, entry_id DESC
                    LIMIT 1
                    """
                ),
                {
                    "org_id": org_id,
                    "repository_id": repository_id,
                    "cache_key": cache_key,
                    "version": version,
                },
            ).mappings().one_or_none()
            if exact:
                return self._row_to_entry(exact)

            for restore_key in restore_keys:
                row = conn.execute(
                    text(
                        """
                        SELECT entry_id, org_id, repository_id, cache_key, version, scope,
                               storage_key, upload_token, download_token, status, size_bytes
                        FROM github_cache_entries
                        WHERE org_id = :org_id
                          AND repository_id = :repository_id
                          AND cache_key LIKE :prefix
                          AND version = :version
                          AND status = 'committed'
                        ORDER BY sequence DESC, updated_at DESC, created_at DESC, entry_id DESC
                        LIMIT 1
                        """
                    ),
                    {
                        "org_id": org_id,
                        "repository_id": repository_id,
                        "prefix": f"{restore_key}%",
                        "version": version,
                    },
                ).mappings().one_or_none()
                if row:
                    return self._row_to_entry(row)

        return None

    def get_by_id(self, entry_id: str) -> GitHubCacheEntry | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT entry_id, org_id, repository_id, cache_key, version, scope,
                           storage_key, upload_token, download_token, status, size_bytes
                    FROM github_cache_entries
                    WHERE entry_id = :entry_id
                    """
                ),
                {"entry_id": entry_id},
            ).mappings().one_or_none()
        if row is None:
            return None
        return self._row_to_entry(row)

    def delete_entry(self, entry_id: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text("DELETE FROM github_cache_entries WHERE entry_id = :entry_id"),
                {"entry_id": entry_id},
            )

    def validate_upload_token(self, entry_id: str, token: str) -> bool:
        with self._engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT upload_token FROM github_cache_entries
                    WHERE entry_id = :entry_id
                    """
                ),
                {"entry_id": entry_id},
            ).mappings().one_or_none()
        if row is None:
            return False
        return row["upload_token"] == token

    def validate_download_token(self, entry_id: str, token: str) -> bool:
        with self._engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT download_token FROM github_cache_entries
                    WHERE entry_id = :entry_id
                    """
                ),
                {"entry_id": entry_id},
            ).mappings().one_or_none()
        if row is None:
            return False
        return row["download_token"] == token

    def record_access(self, entry_id: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE github_cache_entries
                    SET updated_at = CURRENT_TIMESTAMP
                    WHERE entry_id = :entry_id
                    """
                ),
                {"entry_id": entry_id},
            )

    def _initialise(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS github_cache_entries (
                        entry_id TEXT PRIMARY KEY,
                        org_id INTEGER NOT NULL,
                        repository_id INTEGER NOT NULL,
                        cache_key TEXT NOT NULL,
                        version TEXT NOT NULL,
                        scope TEXT NOT NULL,
                        storage_key TEXT NOT NULL,
                        upload_token TEXT NOT NULL,
                        download_token TEXT NOT NULL,
                        status TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        sequence REAL NOT NULL DEFAULT 0,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE INDEX IF NOT EXISTS idx_github_cache_lookup
                    ON github_cache_entries(org_id, repository_id, cache_key, version)
                    """
                )
            )
            try:
                conn.execute(
                    text(
                        """
                        ALTER TABLE github_cache_entries
                        ADD COLUMN sequence REAL NOT NULL DEFAULT 0
                        """
                    )
                )
            except Exception:
                pass

    @staticmethod
    def _row_to_entry(row: Mapping[str, object]) -> GitHubCacheEntry:
        return GitHubCacheEntry(
            entry_id=str(row["entry_id"]),
            org_id=int(row["org_id"]),
            repository_id=int(row["repository_id"]),
            cache_key=str(row["cache_key"]),
            version=str(row["version"]),
            scope=str(row["scope"]),
            storage_key=str(row["storage_key"]),
            upload_token=str(row["upload_token"]),
            download_token=str(row["download_token"]),
            status=str(row["status"]),
            size_bytes=int(row["size_bytes"]),
        )

    @staticmethod
    def _build_storage_key(
        org_id: int,
        repository_id: int,
        cache_key: str,
        version: str,
        entry_id: str,
    ) -> str:
        safe_key = cache_key.replace("/", "__")
        safe_version = version.replace("/", "__")
        return f"org-{org_id}/github/repo-{repository_id}/{safe_version}/{entry_id}-{safe_key}"


def scopes_from_metadata(scopes: Iterable[dict[str, object]]) -> list[str]:
    return [str(scope.get("scope", "")) for scope in scopes]
