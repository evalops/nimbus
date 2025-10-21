from __future__ import annotations

from nimbus.control_plane.app import _extract_metadata


def test_extract_metadata_basic():
    labels = [
        "nimbus",
        "param:lr=0.01",
        "meta:BATCH=32",
        "param:optimizer=adam",
    ]
    metadata = _extract_metadata(labels)
    assert metadata == {
        "lr": "0.01",
        "BATCH": "32",
        "optimizer": "adam",
    }


def test_extract_metadata_flag_label():
    labels = ["meta:requires-human"]
    metadata = _extract_metadata(labels)
    assert metadata == {"requires-human": "true"}
