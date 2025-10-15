"""Uvicorn entrypoint for the Smith logging pipeline."""

from __future__ import annotations

from .app import create_app

app = create_app()
