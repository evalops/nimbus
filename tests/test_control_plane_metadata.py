from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from nimbus.control_plane.app import AppState, RateLimiter


class DummyResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload: list[dict[str, object]] = []

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_publish_job_metadata(monkeypatch):
    mock_post_calls: list[dict] = []

    async def mock_post(url: str, json: dict, headers: dict, timeout: float):  # noqa: ANN001 - test helper signature
        mock_post_calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return DummyResponse(status_code=202)

    http_client = SimpleNamespace(post=mock_post)

    limiter = RateLimiter(limit=10, interval=60)
    state = AppState(
        settings=SimpleNamespace(cache_shared_secret=SimpleNamespace(get_secret_value=lambda: "super-secret")),
        redis=None,
        http_client=http_client,
        github_client=None,
        session_factory=None,
        token_rate_limiter=limiter,
        admin_rate_limiter=limiter,
        metadata_sink_url="http://logging/",
    )

    await state.publish_job_metadata(
        job_id=100,
        run_id=200,
        run_attempt=1,
        org_id=42,
        repo_id=77,
        executor="gpu",
        metadata={"lr": "0.01"},
        status="succeeded",
    )

    assert len(mock_post_calls) == 1
    call = mock_post_calls[0]
    assert call["url"].endswith("/metadata/jobs")
    assert call["headers"]["Authorization"].startswith("Bearer ")
    body = call["json"]
    assert body["records"][0]["key"] == "lr"

    # Empty metadata should short-circuit
    await state.publish_job_metadata(
        job_id=100,
        run_id=200,
        run_attempt=1,
        org_id=42,
        repo_id=77,
        executor="gpu",
        metadata={},
        status="succeeded",
    )
    assert len(mock_post_calls) == 1


@pytest.mark.asyncio
async def test_metadata_summary_cache(monkeypatch):
    payload = [{"value": "0.1", "count": 5}]

    async def mock_get(url: str, params: dict, headers: dict, timeout: float):  # noqa: ANN001
        mock_get.calls += 1  # type: ignore[attr-defined]
        response = DummyResponse(status_code=200)
        response._payload = payload  # type: ignore[attr-defined]
        return response

    mock_get.calls = 0  # type: ignore[attr-defined]

    async def mock_post(*args, **kwargs):  # noqa: ANN001
        return DummyResponse(status_code=202)

    state = AppState(
        settings=SimpleNamespace(cache_shared_secret=SimpleNamespace(get_secret_value=lambda: "super-secret")),
        redis=None,
        http_client=SimpleNamespace(get=mock_get, post=mock_post),
        github_client=None,
        session_factory=None,
        token_rate_limiter=RateLimiter(limit=10, interval=60),
        admin_rate_limiter=RateLimiter(limit=10, interval=60),
        metadata_sink_url="http://logging",
    )

    await state.fetch_metadata_summary(org_id=42, key="lr", limit=5, hours_back=None)
    await state.fetch_metadata_summary(org_id=42, key="lr", limit=5, hours_back=None)
    assert mock_get.calls == 1  # type: ignore[attr-defined]

    await state.publish_job_metadata(
        job_id=200,
        run_id=300,
        run_attempt=1,
        org_id=42,
        repo_id=77,
        executor="gpu",
        metadata={"lr": "0.02"},
        status="succeeded",
    )

    await state.fetch_metadata_summary(org_id=42, key="lr", limit=5, hours_back=None)
    assert mock_get.calls == 2  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_metadata_bundle(monkeypatch):
    state = AppState(
        settings=SimpleNamespace(cache_shared_secret=SimpleNamespace(get_secret_value=lambda: "super-secret")),
        redis=None,
        http_client=None,
        github_client=None,
        session_factory=None,
        token_rate_limiter=RateLimiter(limit=10, interval=60),
        admin_rate_limiter=RateLimiter(limit=10, interval=60),
        metadata_sink_url="http://logging",
    )

    async def fake_summary(**kwargs):  # noqa: ANN001
        return [{"value": "0.1", "count": 5}]

    async def fake_outcomes(**kwargs):  # noqa: ANN001
        return [{"value": "0.1", "total": 5, "succeeded": 4, "failed": 1}]

    async def fake_trend(**kwargs):  # noqa: ANN001
        return [{"window_start": "2024-01-01T00:00:00Z", "total": 5, "succeeded": 4}]

    state.fetch_metadata_summary = fake_summary  # type: ignore[assignment]
    state.fetch_metadata_outcomes = fake_outcomes  # type: ignore[assignment]
    state.fetch_metadata_trend = fake_trend  # type: ignore[assignment]

    bundle = await state.build_metadata_bundle(
        key="lr",
        org_id=42,
        hours_back=24,
        limit=5,
        bucket_hours=1,
    )

    assert bundle["key"] == "lr"
    assert bundle["summary"][0]["count"] == 5
    assert bundle["outcomes"][0]["succeeded"] == 4
    assert bundle["trend"][0]["total"] == 5
