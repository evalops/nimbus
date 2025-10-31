"""Minimal sigstore.verify stub used in tests."""

from __future__ import annotations


class VerificationMaterials:  # pragma: no cover - simple stub
    pass


def verifier(*_args, **_kwargs):  # pragma: no cover - simple stub
    class _Verifier:
        def verify(self, *_a, **_kw):
            return None

    return _Verifier()
