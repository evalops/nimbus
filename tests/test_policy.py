from __future__ import annotations

from nimbus.control_plane.policy import JobPolicy
from nimbus.common.schemas import GitHubRepository, GitHubWorkflowJob, WebhookWorkflowJobEvent


def _make_event(
    *,
    repo_full_name: str = "acme/widget",
    labels: list[str] | None = None,
    display_title: str = "smoke",
) -> WebhookWorkflowJobEvent:
    if labels is None:
        labels = ["nimbus"]
    repository = GitHubRepository(
        id=1,
        name=repo_full_name.split("/")[-1],
        full_name=repo_full_name,
        private=False,
    )
    job = GitHubWorkflowJob(
        id=123,
        run_id=456,
        run_attempt=1,
        status="queued",
        labels=labels,
        display_title=display_title,
    )
    return WebhookWorkflowJobEvent(action="queued", repository=repository, workflow_job=job)


def test_policy_blocks_denied_labels():
    policy = JobPolicy.from_dict({"deny_labels": ["production"]})
    event = _make_event(labels=["nimbus", "production"])
    result = policy.evaluate(event)
    assert not result.allowed
    assert "label" in (result.reason or "")


def test_policy_blocks_non_allowed_repo():
    policy = JobPolicy.from_dict({"allow_repositories": ["acme/widget"]})
    allowed = policy.evaluate(_make_event())
    assert allowed.allowed

    blocked = policy.evaluate(_make_event(repo_full_name="acme/forbidden"))
    assert not blocked.allowed
    assert "allow list" in (blocked.reason or "")
