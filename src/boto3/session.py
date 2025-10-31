"""Minimal subset of boto3.session.Session used in tests."""

from __future__ import annotations

from types import SimpleNamespace


class _StubBody:
    def read(self) -> bytes:  # pragma: no cover - trivial
        return b""


class _StubS3Client:
    def __init__(self) -> None:
        self.exceptions = SimpleNamespace(NoSuchKey=Exception)

    def upload_file(self, *_args, **_kwargs):  # pragma: no cover - trivial
        return None

    def get_object(self, **_kwargs):  # pragma: no cover - trivial
        return {"Body": _StubBody()}

    def head_object(self, **_kwargs):  # pragma: no cover - trivial
        return {"ContentLength": 0}


class Session:  # pragma: no cover - compatibility shim
    def __init__(self, **_kwargs) -> None:
        return

    def client(self, service_name: str, **_kwargs):
        if service_name.lower() != "s3":
            raise NotImplementedError("Stub supports only S3 client")
        return _StubS3Client()
