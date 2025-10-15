"""Uvicorn entrypoint for the Nimbus control plane."""

from __future__ import annotations

from .app import create_app

app = create_app()
