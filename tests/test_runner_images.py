from __future__ import annotations

from nimbus.runners.images import PREBUILT_RUNNER_IMAGES, resolve_prebuilt_image


def test_resolve_prebuilt_image_known_alias() -> None:
    assert resolve_prebuilt_image("ubuntu-2204") == PREBUILT_RUNNER_IMAGES["ubuntu-2204"]


def test_resolve_prebuilt_image_unknown_alias() -> None:
    assert resolve_prebuilt_image("custom-image") is None
