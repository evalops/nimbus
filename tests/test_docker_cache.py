from __future__ import annotations

import hashlib
import json
from datetime import timedelta
import pytest

from nimbus.common.security import mint_cache_token


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _auth_headers(secret: str, scope: str | None = None) -> dict[str, str]:
    token = mint_cache_token(
        secret=secret,
        organization_id=1,
        ttl_seconds=int(timedelta(hours=1).total_seconds()),
        scope=scope,
    )
    return {"Authorization": f"Bearer {token.token}"}


@pytest.mark.anyio("asyncio")
async def test_blob_upload_and_fetch(docker_cache_env) -> None:
    client = docker_cache_env["client"]
    secret = docker_cache_env["secret"]
    repo_scope = "pull:org-1,push:org-1,pull:org-1/nimbus,push:org-1/nimbus"
    headers = await _auth_headers(secret, scope=repo_scope)

    resp = await client.post("/v2/org-1/nimbus/blobs/uploads/", headers=headers)
    assert resp.status_code == 202
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

    blob_resp = await client.get(f"/v2/org-1/nimbus/blobs/{digest}", headers=headers)
    assert blob_resp.status_code == 200
    assert blob_resp.content == content

    head_resp = await client.head(f"/v2/org-1/nimbus/blobs/{digest}", headers=headers)
    assert head_resp.status_code == 200
    assert head_resp.headers["Docker-Content-Digest"] == digest
    assert head_resp.headers["Content-Length"] == str(len(content))


@pytest.mark.anyio("asyncio")
async def test_manifest_roundtrip(docker_cache_env) -> None:
    client = docker_cache_env["client"]
    secret = docker_cache_env["secret"]
    repo_scope = "pull:org-1,push:org-1,pull:org-1/demo,push:org-1/demo"
    headers = await _auth_headers(secret, scope=repo_scope)

    layer_bytes = b"layerdata"
    digest = f"sha256:{hashlib.sha256(layer_bytes).hexdigest()}"
    resp = await client.post("/v2/org-1/demo/blobs/uploads/", headers=headers)
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
        "/v2/org-1/demo/manifests/latest",
        content=manifest_bytes,
        headers={**headers, "content-type": "application/vnd.docker.distribution.manifest.v2+json"},
    )
    assert resp.status_code == 201
    manifest_digest = resp.headers["Docker-Content-Digest"]

    get_resp = await client.get("/v2/org-1/demo/manifests/latest", headers=headers)
    assert get_resp.status_code == 200
    assert json.loads(get_resp.content) == manifest

    digest_resp = await client.get(f"/v2/org-1/demo/manifests/{manifest_digest}", headers=headers)
    assert digest_resp.status_code == 200
    assert json.loads(digest_resp.content) == manifest
    assert digest_resp.headers["Docker-Content-Digest"] == manifest_digest

    head_resp = await client.head(f"/v2/org-1/demo/manifests/{manifest_digest}", headers=headers)
    assert head_resp.status_code == 200
    assert head_resp.headers["Docker-Content-Digest"] == manifest_digest
    assert head_resp.headers["Content-Length"] == str(len(manifest_bytes))

    # org-wide scope access should succeed without repo-specific suffix
    restricted_headers = await _auth_headers(secret, scope="pull:org-1,push:org-1")
    allow_resp = await client.get("/v2/org-1/demo/manifests/latest", headers=restricted_headers)
    assert allow_resp.status_code == 200
    assert json.loads(allow_resp.content) == manifest

    # audit log should record granted access and no denial
    audit_log = docker_cache_env["audit_log"]
    events = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines() if line]
    assert any(
        event["event"] == "docker_cache_access_granted" and event.get("scope") == "pull:org-1,push:org-1"
        for event in events
    )
    assert not any(event["event"] == "docker_cache_access_denied" for event in events)


@pytest.mark.anyio("asyncio")
async def test_digest_mismatch_rejected(docker_cache_env) -> None:
    client = docker_cache_env["client"]
    secret = docker_cache_env["secret"]
    repo_scope = "pull:org-1,push:org-1,pull:org-1/demo,push:org-1/demo"
    headers = await _auth_headers(secret, scope=repo_scope)

    resp = await client.post("/v2/org-1/demo/blobs/uploads/", headers=headers)
    location = resp.headers["Location"]
    bad_digest = "sha256:" + "0" * 64
    resp = await client.put(f"{location}?digest={bad_digest}", content=b"data", headers=headers)
    assert resp.status_code == 400

    blob_resp = await client.get(f"/v2/org-1/demo/blobs/{bad_digest}", headers=headers)
    assert blob_resp.status_code == 404
