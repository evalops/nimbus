from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nimbus.cache_proxy.app import create_app, GITHUB_CACHE_SERVICE_BASE
from nimbus.common.security import mint_cache_token


SECRET = "test-secret"
ORG_ID = 42


@pytest.fixture
def auth_headers() -> dict[str, str]:
    token = mint_cache_token(secret=SECRET, organization_id=ORG_ID, ttl_seconds=3600)
    return {"Authorization": f"Bearer {token.token}"}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    storage = tmp_path / "storage"
    storage.mkdir()
    db_path = tmp_path / "metrics.db"
    monkeypatch.setenv("NIMBUS_CACHE_STORAGE_PATH", storage.as_posix())
    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", SECRET)
    monkeypatch.setenv("NIMBUS_CACHE_METRICS_DB", f"sqlite+pysqlite:///{db_path.as_posix()}")
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def test_github_cache_roundtrip(client: TestClient, auth_headers: dict[str, str]) -> None:
    create_payload = {
        "metadata": {
            "repository_id": 1234,
            "scope": [{"scope": "repository", "permission": 3}],
        },
        "key": "linux-node-modules",
        "version": "v1",
    }

    response = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/CreateCacheEntry",
        json=create_payload,
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    upload_url = body["signed_upload_url"]
    assert upload_url
    upload_token = body["upload_token"]
    assert upload_token

    payload = b"cached-data"
    upload_response = client.put(
        upload_url,
        content=payload,
        headers={"X-GitHub-Cache-Token": upload_token},
    )
    assert upload_response.status_code == 204

    finalize_payload = {
        "metadata": create_payload["metadata"],
        "key": create_payload["key"],
        "size_bytes": len(payload),
        "version": create_payload["version"],
    }
    finalize_response = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/FinalizeCacheEntryUpload",
        json=finalize_payload,
        headers=auth_headers,
    )
    assert finalize_response.status_code == 200
    finalize_body = finalize_response.json()
    assert finalize_body["ok"] is True
    assert finalize_body["entry_id"]

    lookup_payload = {
        "metadata": create_payload["metadata"],
        "key": create_payload["key"],
        "restore_keys": [],
        "version": create_payload["version"],
    }
    lookup_response = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/GetCacheEntryDownloadURL",
        json=lookup_payload,
        headers=auth_headers,
    )
    assert lookup_response.status_code == 200
    lookup_body = lookup_response.json()
    assert lookup_body["ok"] is True
    assert lookup_body["matched_key"] == create_payload["key"]
    download_url = lookup_body["signed_download_url"]
    assert download_url
    download_token = lookup_body["download_token"]
    assert download_token

    download_response = client.get(
        download_url,
        headers={"X-GitHub-Cache-Token": download_token},
    )
    assert download_response.status_code == 200
    assert download_response.content == payload


def test_github_cache_restore_keys(client: TestClient, auth_headers: dict[str, str]) -> None:
    base_metadata = {
        "metadata": {"repository_id": 99, "scope": []},
        "version": "abc123",
    }

    first_payload = {**base_metadata, "key": "linux-node-primary"}
    create_first = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/CreateCacheEntry",
        json=first_payload,
        headers=auth_headers,
    )
    create_first_body = create_first.json()
    upload_url = create_first_body["signed_upload_url"]
    client.put(
        upload_url,
        content=b"first",
        headers={"X-GitHub-Cache-Token": create_first_body["upload_token"]},
    )
    finalize_first = {
        "metadata": first_payload["metadata"],
        "key": first_payload["key"],
        "size_bytes": 5,
        "version": first_payload["version"],
    }
    client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/FinalizeCacheEntryUpload",
        json=finalize_first,
        headers=auth_headers,
    )

    second_payload = {**base_metadata, "key": "linux-node-secondary"}
    create_second = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/CreateCacheEntry",
        json=second_payload,
        headers=auth_headers,
    )
    create_second_body = create_second.json()
    upload_second = create_second_body["signed_upload_url"]
    client.put(
        upload_second,
        content=b"second",
        headers={"X-GitHub-Cache-Token": create_second_body["upload_token"]},
    )
    finalize_second = {
        "metadata": second_payload["metadata"],
        "key": second_payload["key"],
        "size_bytes": 6,
        "version": second_payload["version"],
    }
    client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/FinalizeCacheEntryUpload",
        json=finalize_second,
        headers=auth_headers,
    )

    lookup_payload = {
        "metadata": base_metadata["metadata"],
        "key": "missing",
        "restore_keys": ["linux-node"],
        "version": base_metadata["version"],
    }
    response = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/GetCacheEntryDownloadURL",
        json=lookup_payload,
        headers=auth_headers,
    )
    body = response.json()
    assert body["ok"] is True
    assert body["matched_key"] == "linux-node-secondary"
    download_response = client.get(
        body["signed_download_url"],
        headers={"X-GitHub-Cache-Token": body["download_token"]},
    )
    assert download_response.status_code == 200
    assert download_response.content == b"second"


def test_github_cache_enforces_org_scope(client: TestClient, auth_headers: dict[str, str]) -> None:
    create_payload = {
        "metadata": {"repository_id": 77, "scope": []},
        "key": "scoped-key",
        "version": "scope",
    }
    response = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/CreateCacheEntry",
        json=create_payload,
        headers=auth_headers,
    )
    response_body = response.json()
    upload_url = response_body["signed_upload_url"]
    client.put(
        upload_url,
        content=b"scope",
        headers={"X-GitHub-Cache-Token": response_body["upload_token"]},
    )
    finalize_payload = {
        "metadata": create_payload["metadata"],
        "key": create_payload["key"],
        "size_bytes": 5,
        "version": create_payload["version"],
    }
    client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/FinalizeCacheEntryUpload",
        json=finalize_payload,
        headers=auth_headers,
    )

    other_headers = {
        "Authorization": "Bearer "
        + mint_cache_token(secret=SECRET, organization_id=999, ttl_seconds=3600).token
    }
    lookup_payload = {
        "metadata": create_payload["metadata"],
        "key": create_payload["key"],
        "restore_keys": [],
        "version": create_payload["version"],
    }
    response = client.post(
        f"{GITHUB_CACHE_SERVICE_BASE}/GetCacheEntryDownloadURL",
        json=lookup_payload,
        headers=other_headers,
    )
    assert response.status_code == 200
    assert response.json()["ok"] is False
