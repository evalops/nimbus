"""Minimal botocore.session stub for tests and local development."""

from __future__ import annotations

from types import SimpleNamespace


class Session:  # pragma: no cover - simple compatibility shim
    """Very small subset of ``botocore.session.Session``."""

    def client(self, service_name: str, **_kwargs):
        if service_name.lower() != "s3":
            raise NotImplementedError("Stub client only supports S3")

        def _empty_read():
            return b""

        return SimpleNamespace(
            upload_file=lambda *args, **kwargs: None,
            get_object=lambda **kwargs: {"Body": SimpleNamespace(read=_empty_read)},
            head_object=lambda **kwargs: {"ContentLength": 0},
            exceptions=SimpleNamespace(NoSuchKey=Exception),
        )
