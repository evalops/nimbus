"""Prebuilt runner images maintained by Nimbus."""

from __future__ import annotations

PREBUILT_RUNNER_IMAGES: dict[str, str] = {
    "ubuntu-2404": "nimbus/ubuntu-2404-runner:latest",
    "ubuntu-2204": "nimbus/ubuntu-2204-runner:latest",
    "node-22": "nimbus/node-22-runner:latest",
    "python-312": "nimbus/python-312-runner:latest",
}


def resolve_prebuilt_image(alias: str) -> str | None:
    """Return the canonical image reference for a known alias."""

    return PREBUILT_RUNNER_IMAGES.get(alias)
