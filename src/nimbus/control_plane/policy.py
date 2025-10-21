"""Policy enforcement for incoming GitHub jobs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Iterable, Optional, Tuple

import structlog
import yaml

from ..common.schemas import WebhookWorkflowJobEvent

LOGGER = structlog.get_logger("nimbus.control_plane.policy")


class PolicyError(Exception):
    """Raised when a policy configuration is invalid."""


@dataclass
class EvaluationResult:
    allowed: bool
    reason: Optional[str] = None


def _normalise_entries(entries: Iterable[str] | None) -> set[str]:
    if not entries:
        return set()
    return {item.strip().lower() for item in entries if item and item.strip()}


class JobPolicy:
    """Simple policy engine for webhook jobs."""

    def __init__(
        self,
        *,
        deny_labels: set[str],
        require_labels: set[str],
        allow_repositories: set[str],
        deny_repositories: set[str],
        block_title_patterns: list[re.Pattern[str]],
    ) -> None:
        self._deny_labels = deny_labels
        self._require_labels = require_labels
        self._allow_repositories = allow_repositories
        self._deny_repositories = deny_repositories
        self._block_title_patterns = block_title_patterns

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "JobPolicy":
        deny_labels = _normalise_entries(payload.get("deny_labels"))
        require_labels = _normalise_entries(payload.get("require_labels"))
        allow_repos = _normalise_entries(payload.get("allow_repositories"))
        deny_repos = _normalise_entries(payload.get("deny_repositories"))
        patterns = payload.get("block_title_patterns") or []
        compiled: list[re.Pattern[str]] = []
        for entry in patterns:
            try:
                compiled.append(re.compile(str(entry), flags=re.IGNORECASE))
            except re.error as exc:
                raise PolicyError(f"Invalid regex in block_title_patterns: {entry!r}") from exc
        return cls(
            deny_labels=deny_labels,
            require_labels=require_labels,
            allow_repositories=allow_repos,
            deny_repositories=deny_repos,
            block_title_patterns=compiled,
        )

    def evaluate(self, event: WebhookWorkflowJobEvent) -> EvaluationResult:
        repo_full_name = (event.repository.full_name or "").lower()
        labels = _normalise_entries(event.workflow_job.labels)

        if self._allow_repositories and repo_full_name not in self._allow_repositories:
            return EvaluationResult(False, f"repository {event.repository.full_name} not in allow list")
        if self._deny_repositories and repo_full_name in self._deny_repositories:
            return EvaluationResult(False, f"repository {event.repository.full_name} denied")

        blocked = self._deny_labels.intersection(labels)
        if blocked:
            label = next(iter(blocked))
            return EvaluationResult(False, f"label '{label}' denied")

        missing = [label for label in self._require_labels if label not in labels]
        if missing:
            return EvaluationResult(False, f"missing required label '{missing[0]}'")

        title_candidates = [
            event.workflow_job.display_title or "",
            event.workflow_job.workflow_name or "",
        ]
        for pattern in self._block_title_patterns:
            for candidate in title_candidates:
                if candidate and pattern.search(candidate):
                    return EvaluationResult(False, f"title matched forbidden pattern '{pattern.pattern}'")

        return EvaluationResult(True, None)


def load_job_policy(path: Optional[Path]) -> Optional[JobPolicy]:
    if path is None:
        return None
    if not path.exists():
        raise FileNotFoundError(f"Job policy file not found at {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        LOGGER.info("Loaded empty job policy", path=str(path))
        return None
    if not isinstance(data, dict):
        raise PolicyError("Policy file must contain a mapping at the top level")
    policy = JobPolicy.from_dict(data)
    LOGGER.info(
        "Loaded job policy",
        path=str(path),
        deny_labels=len(policy._deny_labels),
        require_labels=len(policy._require_labels),
        allow_repositories=len(policy._allow_repositories),
        deny_repositories=len(policy._deny_repositories),
        block_title_patterns=len(policy._block_title_patterns),
    )
    return policy
