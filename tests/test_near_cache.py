from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from fastapi import HTTPException

from nimbus.common.schemas import CacheToken, GitHubRepository, JobAssignment, RunnerRegistrationToken
from nimbus.host_agent.near_cache import NearRunnerCacheManager, NearCacheBinding, _CacheState, _enforce_scope, _iter_bytes


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _make_assignment(job_id: int = 101) -> JobAssignment:
    repo = GitHubRepository(id=1, name="demo", full_name="acme/demo", private=False, owner_id=999)
    registration = RunnerRegistrationToken(token="token", expires_at=datetime.now(UTC))
    return JobAssignment(
        job_id=job_id,
        run_id=1,
        run_attempt=1,
        repository=repo,
        labels=["firecracker"],
        runner_registration=registration,
    )


@pytest.mark.anyio
async def test_cache_state_write_read_roundtrip(tmp_path) -> None:
    state = _CacheState(
        storage_dir=tmp_path,
        shared_secret="secret",
        s3_client=None,
        s3_bucket=None,
        write_through=False,
    )

    await state.write(42, "artifacts/build.zip", _iter_bytes(b"payload"))
    data = await state.read(42, "artifacts/build.zip")
    assert data == b"payload"
    size = await state.size(42, "artifacts/build.zip")
    assert size == len(b"payload")


@pytest.mark.anyio
async def test_cache_state_rejects_traversal(tmp_path) -> None:
    state = _CacheState(
        storage_dir=tmp_path,
        shared_secret="secret",
        s3_client=None,
        s3_bucket=None,
        write_through=False,
    )

    with pytest.raises(HTTPException) as exc:
        await state.write(7, "../etc/passwd", _iter_bytes(b"x"))
    assert exc.value.status_code == 400


def test_enforce_scope_validates_operation() -> None:
    token = CacheToken(
        token="tok",
        organization_id=9,
        expires_at=datetime.now(UTC),
        scope="pull:org-9",
    )

    # Pull operation allowed, push should be rejected
    _enforce_scope(token, "path/file", "pull")
    with pytest.raises(HTTPException):
        _enforce_scope(token, "path/file", "push")


def test_binding_metadata_includes_endpoints(tmp_path) -> None:
    settings = SimpleNamespace(
        near_runner_cache_enabled=True,
        near_runner_cache_directory=str(tmp_path),
        near_runner_cache_bind_address="0.0.0.0",
        near_runner_cache_advertise_host="198.51.100.10",
        near_runner_cache_port=38500,
        near_runner_cache_port_start=38000,
        near_runner_cache_port_end=39000,
        near_runner_cache_mount_tag="nimbus-cache",
        near_runner_cache_mount_path="/mnt/nimbus-cache",
        near_runner_cache_s3_bucket=None,
        near_runner_cache_s3_endpoint=None,
        near_runner_cache_s3_region=None,
        near_runner_cache_s3_write_through=False,
        cache_proxy_url=None,
        cache_shared_secret=SimpleNamespace(get_secret_value=lambda: "cache-secret"),
    )

    manager = NearRunnerCacheManager(settings)
    binding = manager.binding_for(_make_assignment(), "10.0.0.5")
    assert isinstance(binding, NearCacheBinding)
    assert binding.host_endpoint == "http://198.51.100.10:38500/cache/"
    assert binding.guest_endpoint == "http://10.0.0.5:38500/cache/"
    assert binding.mount_tag == "nimbus-cache"
    assert binding.mount_path == "/mnt/nimbus-cache"
