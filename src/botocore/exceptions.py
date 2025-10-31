"""Minimal botocore.exceptions stub used in tests."""

from __future__ import annotations


class ClientError(Exception):
    """Placeholder implementation matching botocore.exceptions.ClientError."""

    def __init__(self, error_response=None, operation_name=None):  # noqa: D401 - match botocore signature
        super().__init__(error_response, operation_name)


class DataNotFoundError(Exception):
    """Minimal stand-in for botocore.exceptions.DataNotFoundError."""

    pass


class UnknownServiceError(Exception):
    """Minimal stand-in for botocore.exceptions.UnknownServiceError."""

    pass
