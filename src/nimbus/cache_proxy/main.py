"""Uvicorn entrypoint for the Nimbus cache proxy."""

from __future__ import annotations

from .app import create_app

app = create_app()
