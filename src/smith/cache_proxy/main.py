"""Uvicorn entrypoint for the Smith cache proxy."""

from __future__ import annotations

from .app import create_app

app = create_app()
