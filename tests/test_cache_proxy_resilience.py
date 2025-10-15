from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, status

from smith.cache_proxy.app import S3CacheBackend
from smith.common.settings import CacheProxySettings


class FakeClient:
    class _NoSuchKey(Exception):
        pass

    exceptions = SimpleNamespace(NoSuchKey=_NoSuchKey)

    def __init__(self) -> None:
        self.put_calls = 0
        self.head_calls = 0
        self.get_calls = 0
        self.failures_remaining = 0
        self.response_content_length = 0

    def put_object(self, **kwargs):
        self.put_calls += 1
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            raise RuntimeError("put failure")
        return {}

    def head_object(self, **kwargs):
        self.head_calls += 1
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            raise RuntimeError("head failure")
        return {"ContentLength": self.response_content_length}

    def get_object(self, **kwargs):
        self.get_calls += 1
        if self.failures_remaining > 0:
            self.failures_remaining -= 1
            raise RuntimeError("get failure")

        class Body:
            def __init__(self, payload: bytes) -> None:
                self._payload = payload

            def read(self) -> bytes:
                return self._payload

        return {"Body": Body(b"payload")}


@pytest.fixture
def fake_session(monkeypatch):
    client = FakeClient()

    class DummySession:
        def client(self, *_args, **_kwargs):  # noqa: D401 - mimic boto3 session
            return client

    monkeypatch.setattr("smith.cache_proxy.app.boto3.session.Session", lambda: DummySession())
    return client


@pytest.mark.asyncio
async def test_s3_backend_retries_until_success(fake_session):
    settings = CacheProxySettings(
        shared_secret="secret",
        s3_bucket="bucket",
        s3_endpoint_url="http://example.com",
        s3_max_retries=2,
        s3_retry_base_seconds=0.0,
        s3_retry_max_seconds=0.0,
    )
    backend = S3CacheBackend(settings)
    fake_session.failures_remaining = 1

    async def data_iter():
        yield b"data"

    await backend.write("key", data_iter())
    assert fake_session.put_calls == 2


@pytest.mark.asyncio
async def test_s3_circuit_breaker_blocks_after_failures(monkeypatch, fake_session):
    current_time = [0.0]

    def fake_monotonic():
        return current_time[0]

    monkeypatch.setattr("smith.cache_proxy.app.time.monotonic", fake_monotonic)

    settings = CacheProxySettings(
        shared_secret="secret",
        s3_bucket="bucket",
        s3_endpoint_url="http://example.com",
        s3_max_retries=0,
        s3_retry_base_seconds=0.0,
        s3_retry_max_seconds=0.0,
        s3_circuit_breaker_failures=2,
        s3_circuit_breaker_reset_seconds=5.0,
    )
    backend = S3CacheBackend(settings)
    fake_session.failures_remaining = 10

    with pytest.raises(HTTPException) as exc1:
        await backend.head("key")
    assert exc1.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    with pytest.raises(HTTPException) as exc2:
        await backend.head("key")
    assert exc2.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    first_two_calls = fake_session.head_calls

    with pytest.raises(HTTPException) as exc3:
        await backend.head("key")
    assert exc3.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert fake_session.head_calls == first_two_calls

    fake_session.failures_remaining = 0
    fake_session.response_content_length = 42
    current_time[0] += 6.0

    size = await backend.head("key")
    assert size == 42
    assert fake_session.head_calls == first_two_calls + 1
