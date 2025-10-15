from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from nimbus.common.security import mint_cache_token
from nimbus.docker_cache.app import create_app


async def _create_client(app):
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    client = httpx.AsyncClient(app=app, base_url="http://testserver")
    return client, lifespan


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _auth_headers(secret: str) -> dict[str, str]:
    token = mint_cache_token(secret=secret, organization_id=1, ttl_seconds=int(timedelta(hours=1).total_seconds()))
    return {"Authorization": f"Bearer {token.token}"}


@pytest.mark.anyio("asyncio")
async def test_blob_upload_and_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    storage = tmp_path / "storage"
    uploads = tmp_path / "uploads"
    db_path = tmp_path / "db.sqlite"
    secret = "cache-secret"
    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", secret)
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_STORAGE_PATH", str(storage))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_UPLOAD_PATH", str(uploads))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_DB_PATH", str(db_path))

    app = create_app()
    client, lifespan = await _create_client(app)
    headers = await _auth_headers(secret)

    try:
        resp = await client.post("/v2/nimbus/cache/blobs/uploads/", headers=headers)
        assert resp.status_code == 202
        upload_uuid = resp.headers["Docker-Upload-UUID"]
        location = resp.headers["Location"]

        chunk_one = b"hello "
        resp = await client.patch(location, content=chunk_one, headers=headers)
        assert resp.status_code == 202

        final_chunk = b"world"
        content = chunk_one + final_chunk
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        resp = await client.put(f"{location}?digest={digest}", content=final_chunk, headers=headers)
        assert resp.status_code == 201
        assert resp.headers["Docker-Content-Digest"] == digest

        blob_resp = await client.get(f"/v2/nimbus/cache/blobs/{digest}", headers=headers)
        assert blob_resp.status_code == 200
        assert blob_resp.content == content

        head_resp = await client.head(f"/v2/nimbus/cache/blobs/{digest}", headers=headers)
        assert head_resp.status_code == 200
        assert head_resp.headers["Docker-Content-Digest"] == digest
        assert head_resp.headers["Content-Length"] == str(len(content))
    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)


@pytest.mark.anyio("asyncio")
async def test_manifest_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    storage = tmp_path / "storage"
    uploads = tmp_path / "uploads"
    db_path = tmp_path / "db.sqlite"
    secret = "cache-secret"
    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", secret)
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_STORAGE_PATH", str(storage))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_UPLOAD_PATH", str(uploads))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_DB_PATH", str(db_path))

    app = create_app()
    client, lifespan = await _create_client(app)
    headers = await _auth_headers(secret)

    try:
        layer_bytes = b"layerdata"
        digest = f"sha256:{hashlib.sha256(layer_bytes).hexdigest()}"
        resp = await client.post("/v2/demo/app/blobs/uploads/", headers=headers)
        upload_location = resp.headers["Location"]
        await client.put(f"{upload_location}?digest={digest}", content=layer_bytes, headers=headers)

        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 2,
                "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest(),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar",
                    "size": len(layer_bytes),
                    "digest": digest,
                }
            ],
        }
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        resp = await client.put(
            "/v2/demo/app/manifests/latest",
            content=manifest_bytes,
            headers={**headers, "content-type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        assert resp.status_code == 201
        manifest_digest = resp.headers["Docker-Content-Digest"]

        get_resp = await client.get("/v2/demo/app/manifests/latest", headers=headers)
        assert get_resp.status_code == 200
        assert json.loads(get_resp.content) == manifest

        digest_resp = await client.get(f"/v2/demo/app/manifests/{manifest_digest}", headers=headers)
        assert digest_resp.status_code == 200
        assert json.loads(digest_resp.content) == manifest
        assert digest_resp.headers["Docker-Content-Digest"] == manifest_digest

        head_resp = await client.head(f"/v2/demo/app/manifests/{manifest_digest}", headers=headers)
        assert head_resp.status_code == 200
        assert head_resp.headers["Docker-Content-Digest"] == manifest_digest
        assert head_resp.headers["Content-Length"] == str(len(manifest_bytes))
    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)


@pytest.mark.anyio("asyncio")
async def test_digest_mismatch_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    storage = tmp_path / "storage"
    uploads = tmp_path / "uploads"
    db_path = tmp_path / "db.sqlite"
    secret = "cache-secret"
    monkeypatch.setenv("NIMBUS_CACHE_SHARED_SECRET", secret)
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_STORAGE_PATH", str(storage))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_UPLOAD_PATH", str(uploads))
    monkeypatch.setenv("NIMBUS_DOCKER_CACHE_DB_PATH", str(db_path))

    app = create_app()
    client, lifespan = await _create_client(app)
    headers = await _auth_headers(secret)

    try:
        resp = await client.post("/v2/demo/app/blobs/uploads/", headers=headers)
        location = resp.headers["Location"]
        bad_digest = "sha256:" + "0" * 64
        resp = await client.put(f"{location}?digest={bad_digest}", content=b"data", headers=headers)
        assert resp.status_code == 400

        blob_resp = await client.get(f"/v2/demo/app/blobs/{bad_digest}", headers=headers)
        assert blob_resp.status_code == 404
    finally:
        await client.aclose()
        await lifespan.__aexit__(None, None, None)
